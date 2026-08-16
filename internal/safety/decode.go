// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package safety

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

type controlFlow uint8

const (
	flowNone controlFlow = iota
	flowCall
	flowJump
)

type instructionSemantics struct {
	flow         controlFlow
	direct       bool
	directTarget uint64
	indirect     bool
	ripReference bool
	ripTarget    uint64
}

func decodeSemantics(instruction x86.Instruction, mode x86.Mode) (instructionSemantics, error) {
	var result instructionSemantics
	raw := instruction.Bytes
	if len(raw) == 0 {
		return result, fmt.Errorf("decoded instruction has no bytes")
	}
	mnemonic := strings.ToLower(strings.TrimSpace(instruction.Mnemonic))
	opcodeAt, rexW, addressOverride := opcodeOffset(raw, mode)
	if opcodeAt >= len(raw) {
		return result, fmt.Errorf("instruction consists only of prefixes")
	}
	opcode := raw[opcodeAt]

	switch opcode {
	case 0xe8, 0xe9:
		want := "call"
		result.flow = flowCall
		if opcode == 0xe9 {
			want = "jmp"
			result.flow = flowJump
		}
		if mnemonic != want {
			return result, fmt.Errorf("opcode %#x decoded as %q, want %s", opcode, mnemonic, want)
		}
		immediate := raw[opcodeAt+1:]
		var displacement int64
		switch len(immediate) {
		case 2:
			if mode != x86.Mode32 {
				return result, fmt.Errorf("%s has unsupported 16-bit displacement in %s mode", want, mode)
			}
			displacement = int64(int16(binary.LittleEndian.Uint16(immediate)))
		case 4:
			displacement = int64(int32(binary.LittleEndian.Uint32(immediate)))
		default:
			return result, fmt.Errorf("%s relative displacement is %d bytes", want, len(immediate))
		}
		target, err := addRelative(instruction.Address, len(raw), displacement)
		if err != nil {
			return result, err
		}
		result.direct = true
		result.directTarget = target
		return result, nil

	case 0xeb:
		if mnemonic != "jmp" {
			return result, fmt.Errorf("opcode %#x decoded as %q, want jmp", opcode, mnemonic)
		}
		if len(raw[opcodeAt+1:]) != 1 {
			return result, fmt.Errorf("short jmp displacement is %d bytes", len(raw[opcodeAt+1:]))
		}
		target, err := addRelative(instruction.Address, len(raw), int64(int8(raw[opcodeAt+1])))
		if err != nil {
			return result, err
		}
		result.flow = flowJump
		result.direct = true
		result.directTarget = target
		return result, nil

	case 0xff:
		if opcodeAt+1 >= len(raw) {
			return result, fmt.Errorf("truncated FF control-flow encoding")
		}
		modRM := raw[opcodeAt+1]
		operation := (modRM >> 3) & 7
		switch operation {
		case 2:
			result.flow = flowCall
			if mnemonic != "call" {
				return result, fmt.Errorf("FF /2 decoded as %q, want call", mnemonic)
			}
		case 4:
			result.flow = flowJump
			if mnemonic != "jmp" {
				return result, fmt.Errorf("FF /4 decoded as %q, want jmp", mnemonic)
			}
		default:
			if mnemonic == "call" || mnemonic == "jmp" {
				return result, fmt.Errorf("%s uses unsupported FF /%d encoding", mnemonic, operation)
			}
			return result, nil
		}
		result.indirect = true
		if mode == x86.Mode64 && !addressOverride && modRM>>6 == 0 && modRM&7 == 5 {
			target, ok, err := ripRelativeTarget(instruction, opcodeAt+2)
			if err != nil {
				return result, err
			}
			if !ok {
				return result, fmt.Errorf("%s RIP-relative operand has an unsupported encoding", mnemonic)
			}
			result.ripReference = true
			result.ripTarget = target
		}
		return result, nil
	}

	if mnemonic == "call" {
		result.flow = flowCall
		result.indirect = true
		return result, nil
	}
	if mnemonic == "jmp" {
		result.flow = flowJump
		result.indirect = true
		return result, nil
	}

	if mode != x86.Mode64 || (mnemonic != "lea" && mnemonic != "mov") {
		return result, nil
	}
	wantRIP := strings.Contains(strings.ToLower(instruction.Operands), "rip")
	validOpcode := opcode == 0x8d
	if mnemonic == "mov" {
		// This is upstream's MOV r64, r/m64 form. Other MOV forms are not
		// CallWalk references even when they happen to use an address.
		validOpcode = rexW && opcode == 0x8b
	}
	if !validOpcode || opcodeAt+1 >= len(raw) {
		if wantRIP {
			return result, fmt.Errorf("%s reports RIP-relative operands with an unsupported encoding", mnemonic)
		}
		return result, nil
	}
	modRM := raw[opcodeAt+1]
	if addressOverride || modRM>>6 != 0 || modRM&7 != 5 {
		if wantRIP {
			return result, fmt.Errorf("%s reports RIP-relative operands without RIP-relative ModRM", mnemonic)
		}
		return result, nil
	}
	target, ok, err := ripRelativeTarget(instruction, opcodeAt+2)
	if err != nil {
		return result, err
	}
	if !ok {
		return result, fmt.Errorf("%s RIP-relative operand has an unsupported encoding", mnemonic)
	}
	result.ripReference = true
	result.ripTarget = target
	return result, nil
}

func opcodeOffset(raw []byte, mode x86.Mode) (offset int, rexW, addressOverride bool) {
	for offset < len(raw) {
		switch raw[offset] {
		case 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66:
			offset++
			continue
		case 0x67:
			addressOverride = true
			offset++
			continue
		}
		if mode == x86.Mode64 && raw[offset] >= 0x40 && raw[offset] <= 0x4f {
			rexW = raw[offset]&8 != 0
			offset++
			continue
		}
		break
	}
	return offset, rexW, addressOverride
}

func ripRelativeTarget(instruction x86.Instruction, displacementOffset int) (uint64, bool, error) {
	if displacementOffset < 0 || displacementOffset+4 != len(instruction.Bytes) {
		return 0, false, nil
	}
	displacement := int64(int32(binary.LittleEndian.Uint32(instruction.Bytes[displacementOffset:])))
	target, err := addRelative(instruction.Address, len(instruction.Bytes), displacement)
	if err != nil {
		return 0, false, err
	}
	return target, true, nil
}

func addRelative(address uint64, length int, displacement int64) (uint64, error) {
	if length < 0 || uint64(length) > math.MaxUint64-address {
		return 0, fmt.Errorf("instruction end address overflows")
	}
	base := address + uint64(length)
	if displacement < 0 {
		magnitude := uint64(-(displacement + 1)) + 1
		if magnitude > base {
			return 0, fmt.Errorf("relative target precedes address zero")
		}
		return base - magnitude, nil
	}
	if uint64(displacement) > math.MaxUint64-base {
		return 0, fmt.Errorf("relative target overflows")
	}
	return base + uint64(displacement), nil
}
