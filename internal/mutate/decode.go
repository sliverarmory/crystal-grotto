// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package mutate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

type candidateKind uint8

const (
	candidateNone candidateKind = iota
	candidateCMPRegImm32
	candidateMOVRegImm32
	candidateMOVRegImm64
	candidateMOVStackImm32
	candidatePUSHImm32
)

type candidate struct {
	kind      candidateKind
	register  uint8
	immediate uint64
	memory    stackMemory
}

type stackMemory struct {
	base     uint8
	displace int64
	segment  byte
}

type prefixes struct {
	opcodeOffset int
	segment      byte
	operand16    bool
	address32    bool
	rex          byte
	noncanonical bool
}

func decodeCandidate(raw []byte, machine coff.Machine) (candidate, bool, error) {
	mode64 := machine == coff.MachineAMD64
	prefix, err := parsePrefixes(raw, mode64)
	if err != nil {
		return candidate{}, false, err
	}
	if prefix.opcodeOffset >= len(raw) {
		return candidate{}, false, errors.New("instruction contains only prefixes")
	}
	opcode := raw[prefix.opcodeOffset]
	rexW := prefix.rex&8 != 0
	rexB := uint8((prefix.rex >> 0) & 1)

	switch {
	case opcode >= 0xb8 && opcode <= 0xbf:
		if prefix.operand16 {
			return candidate{}, false, nil
		}
		register := uint8(opcode-0xb8) | rexB<<3
		if rexW {
			if !mode64 {
				return candidate{}, false, errors.New("REX.W outside 64-bit mode")
			}
			if err := requireCanonicalCandidate(prefix, false); err != nil {
				return candidate{}, false, err
			}
			if prefix.opcodeOffset+9 != len(raw) {
				return candidate{}, false, errors.New("MOV r64, imm64 has an unexpected length")
			}
			value := binary.LittleEndian.Uint64(raw[prefix.opcodeOffset+1:])
			if value == 0 {
				return candidate{}, false, nil
			}
			return candidate{kind: candidateMOVRegImm64, register: register, immediate: value}, true, nil
		}
		if err := requireCanonicalCandidate(prefix, false); err != nil {
			return candidate{}, false, err
		}
		if prefix.opcodeOffset+5 != len(raw) {
			return candidate{}, false, errors.New("MOV r32, imm32 has an unexpected length")
		}
		value := int32(binary.LittleEndian.Uint32(raw[prefix.opcodeOffset+1:]))
		if !safeImmediate32(value) {
			return candidate{}, false, nil
		}
		return candidate{kind: candidateMOVRegImm32, register: register, immediate: uint64(uint32(value))}, true, nil

	case opcode == 0x3d:
		if prefix.operand16 || rexW {
			return candidate{}, false, nil
		}
		if err := requireCanonicalCandidate(prefix, false); err != nil {
			return candidate{}, false, err
		}
		if prefix.opcodeOffset+5 != len(raw) {
			return candidate{}, false, errors.New("CMP EAX, imm32 has an unexpected length")
		}
		value := int32(binary.LittleEndian.Uint32(raw[prefix.opcodeOffset+1:]))
		if !safeImmediate32(value) {
			return candidate{}, false, nil
		}
		return candidate{kind: candidateCMPRegImm32, register: 0, immediate: uint64(uint32(value))}, true, nil

	case opcode == 0x81:
		if prefix.opcodeOffset+2 > len(raw) {
			return candidate{}, false, errors.New("truncated opcode 81 instruction")
		}
		modRM := raw[prefix.opcodeOffset+1]
		if (modRM>>3)&7 != 7 || modRM>>6 != 3 || prefix.operand16 || rexW {
			return candidate{}, false, nil
		}
		if prefix.rex&4 != 0 {
			return candidate{}, false, errors.New("CMP r/m32, imm32 has a noncanonical REX.R bit")
		}
		if err := requireCanonicalCandidate(prefix, false); err != nil {
			return candidate{}, false, err
		}
		if prefix.opcodeOffset+6 != len(raw) {
			return candidate{}, false, errors.New("CMP r/m32, imm32 has an unexpected length")
		}
		value := int32(binary.LittleEndian.Uint32(raw[prefix.opcodeOffset+2:]))
		if !safeImmediate32(value) {
			return candidate{}, false, nil
		}
		register := uint8(modRM&7) | rexB<<3
		return candidate{kind: candidateCMPRegImm32, register: register, immediate: uint64(uint32(value))}, true, nil

	case opcode == 0xc7:
		if prefix.opcodeOffset+2 > len(raw) {
			return candidate{}, false, errors.New("truncated MOV r/m32, imm32")
		}
		modRM := raw[prefix.opcodeOffset+1]
		if (modRM>>3)&7 != 0 || modRM>>6 == 3 || prefix.operand16 || rexW {
			return candidate{}, false, nil
		}
		memory, immediateOffset, desired, err := decodeStackMemory(raw, prefix, mode64)
		if err != nil {
			return candidate{}, false, err
		}
		if !desired {
			return candidate{}, false, nil
		}
		if immediateOffset+4 != len(raw) {
			return candidate{}, false, errors.New("MOV r/m32, imm32 has an unexpected immediate location")
		}
		value := int32(binary.LittleEndian.Uint32(raw[immediateOffset:]))
		if !safeImmediate32(value) {
			return candidate{}, false, nil
		}
		return candidate{kind: candidateMOVStackImm32, immediate: uint64(uint32(value)), memory: memory}, true, nil

	case opcode == 0x68:
		if mode64 || prefix.operand16 {
			return candidate{}, false, nil
		}
		if err := requireCanonicalCandidate(prefix, false); err != nil {
			return candidate{}, false, err
		}
		if prefix.opcodeOffset+5 != len(raw) {
			return candidate{}, false, errors.New("PUSH imm32 has an unexpected length")
		}
		value := int32(binary.LittleEndian.Uint32(raw[prefix.opcodeOffset+1:]))
		if !safeImmediate32(value) {
			return candidate{}, false, nil
		}
		return candidate{kind: candidatePUSHImm32, immediate: uint64(uint32(value))}, true, nil
	}
	return candidate{}, false, nil
}

func parsePrefixes(raw []byte, mode64 bool) (prefixes, error) {
	var result prefixes
	index := 0
	for index < len(raw) {
		switch raw[index] {
		case 0x26, 0x2e, 0x36, 0x3e:
			// Upstream only carries FS/GS through getMemOperand(). Other
			// redundant segment prefixes disappear from generated code.
			result.noncanonical = true
			index++
		case 0x64, 0x65:
			if result.segment != 0 {
				result.noncanonical = true
			}
			result.segment = raw[index]
			index++
		case 0x66:
			result.operand16 = true
			index++
		case 0x67:
			result.address32 = true
			index++
		case 0xf0, 0xf2, 0xf3:
			result.noncanonical = true
			index++
		default:
			goto legacyDone
		}
	}

legacyDone:
	if mode64 {
		for index < len(raw) && raw[index] >= 0x40 && raw[index] <= 0x4f {
			if result.rex != 0 {
				result.noncanonical = true
			}
			result.rex = raw[index]
			index++
		}
	}
	result.opcodeOffset = index
	return result, nil
}

func requireCanonicalCandidate(prefix prefixes, memory bool) error {
	if prefix.noncanonical {
		return errors.New("candidate uses prefixes whose upstream re-encoding cannot be proven")
	}
	if !memory && prefix.segment != 0 {
		return errors.New("register candidate has a redundant segment prefix")
	}
	if !memory && prefix.address32 {
		return errors.New("register candidate has a redundant address-size prefix")
	}
	return nil
}

func decodeStackMemory(raw []byte, prefix prefixes, mode64 bool) (stackMemory, int, bool, error) {
	if prefix.noncanonical {
		return stackMemory{}, 0, false, errors.New("stack-memory candidate uses unsupported prefixes")
	}
	if mode64 && prefix.address32 {
		return stackMemory{}, 0, false, errors.New("x64 stack-memory candidate uses 32-bit addressing")
	}
	if !mode64 && prefix.address32 {
		return stackMemory{}, 0, false, errors.New("x86 stack-memory candidate uses 16-bit addressing")
	}
	if prefix.rex&5 != 0 {
		// REX.X introduces an index where SIB index=4 would otherwise mean
		// none; REX.B changes RSP/RBP into R12/R13, which upstream excludes.
		return stackMemory{}, 0, false, nil
	}
	modRMOffset := prefix.opcodeOffset + 1
	modRM := raw[modRMOffset]
	mod := modRM >> 6
	rm := modRM & 7
	index := modRMOffset + 1
	base := rm
	if rm == 4 {
		if index >= len(raw) {
			return stackMemory{}, 0, false, errors.New("truncated SIB byte")
		}
		sib := raw[index]
		index++
		if (sib>>3)&7 != 4 {
			return stackMemory{}, 0, false, nil
		}
		base = sib & 7
	}
	if base != 4 && base != 5 {
		return stackMemory{}, 0, false, nil
	}
	if mod == 0 && base == 5 {
		return stackMemory{}, 0, false, nil
	}
	var displacement int64
	switch mod {
	case 0:
	case 1:
		if index >= len(raw) {
			return stackMemory{}, 0, false, errors.New("truncated disp8")
		}
		displacement = int64(int8(raw[index]))
		index++
	case 2:
		if index+4 > len(raw) {
			return stackMemory{}, 0, false, errors.New("truncated disp32")
		}
		displacement = int64(int32(binary.LittleEndian.Uint32(raw[index:])))
		index += 4
	default:
		return stackMemory{}, 0, false, nil
	}
	return stackMemory{
		base:     base,
		displace: displacement,
		segment:  prefix.segment,
	}, index, true, nil
}

func safeImmediate32(value int32) bool {
	// Math.abs(Integer.MIN_VALUE) remains negative in Java.
	if value == math.MinInt32 {
		return false
	}
	absolute := int64(value)
	if absolute < 0 {
		absolute = -absolute
	}
	return absolute > 0xff && value%0x400 != 0 && value != 0xffff
}

func (c candidate) changesFlagsBeforeResult() bool {
	return c.kind != candidateCMPRegImm32
}

func (c candidate) encode(random int32Random, pool []uint32, machine coff.Machine) ([]byte, int, error) {
	mode64 := machine == coff.MachineAMD64
	constant := int32(uint32(c.immediate))
	switch c.kind {
	case candidateCMPRegImm32:
		temporary := uint8(3) // EBX
		if c.register == 3 {
			temporary = 7 // EDI is the first upstream alternative.
		}
		output := encodePushRegister(temporary, mode64)
		built, draws, err := buildConstant(random, pool, temporary, constant, mode64)
		if err != nil {
			return nil, draws, err
		}
		output = append(output, built...)
		output = append(output, encodeCMPRegisters(c.register, temporary, mode64)...)
		output = append(output, encodePopRegister(temporary, mode64)...)
		return output, draws, nil

	case candidateMOVRegImm32:
		return buildConstant(random, pool, c.register, constant, mode64)

	case candidateMOVRegImm64:
		if !mode64 {
			return nil, 0, errors.New("MOV r64, imm64 outside x64 mode")
		}
		low := int32(uint32(c.immediate))
		high := int32(uint32(c.immediate >> 32))
		lowCode, lowDraws, err := buildConstant(random, pool, c.register, low, true)
		if err != nil {
			return nil, lowDraws, err
		}
		highCode, highDraws, err := buildConstant(random, pool, c.register, high, true)
		if err != nil {
			return nil, lowDraws + highDraws, err
		}
		output := append([]byte(nil), lowCode...)
		output = append(output, encodePushRegister(c.register, true)...)
		output = append(output, highCode...)
		stack := stackMemory{base: 4, displace: 4}
		store, err := encodeMOVMemoryRegister(stack, c.register, true)
		if err != nil {
			return nil, lowDraws + highDraws, err
		}
		output = append(output, store...)
		output = append(output, encodePopRegister(c.register, true)...)
		return output, lowDraws + highDraws, nil

	case candidateMOVStackImm32:
		temporary := uint8(3) // EBX/RBX
		output := encodePushRegister(temporary, mode64)
		built, draws, err := buildConstant(random, pool, temporary, constant, mode64)
		if err != nil {
			return nil, draws, err
		}
		memory := c.memory
		adjustment := int64(4)
		if mode64 {
			adjustment = 8
		}
		if memory.base == 4 {
			if memory.displace > math.MaxInt32-adjustment {
				return nil, draws, errors.New("stack displacement overflows disp32 after push adjustment")
			}
			memory.displace += adjustment
		}
		store, err := encodeMOVMemoryRegister(memory, temporary, mode64)
		if err != nil {
			return nil, draws, err
		}
		output = append(output, built...)
		output = append(output, store...)
		output = append(output, encodePopRegister(temporary, mode64)...)
		return output, draws, nil

	case candidatePUSHImm32:
		if mode64 {
			return nil, 0, errors.New("PUSH imm32 mutator is x86-only")
		}
		temporary := uint8(3)
		output := encodePushRegister(temporary, false)
		built, draws, err := buildConstant(random, pool, temporary, constant, false)
		if err != nil {
			return nil, draws, err
		}
		output = append(output, built...)
		// xchg dword ptr [esp], ebx
		output = append(output, 0x87, 0x1c, 0x24)
		return output, draws, nil
	default:
		return nil, 0, errors.New("invalid mutation candidate")
	}
}

func buildConstant(random int32Random, pool []uint32, register uint8, constant int32, mode64 bool) ([]byte, int, error) {
	magic, err := chooseMagic(random, pool)
	if err != nil {
		return nil, 1, err
	}
	if !safeImmediate32(constant) {
		return encodeMOVRegister32(register, constant, mode64), 1, nil
	}
	blinded := int32(uint32(constant) - uint32(magic))
	output := encodeMOVRegister32(register, blinded, mode64)
	output = append(output, encodeADDRegister32(register, magic, mode64)...)
	return output, 1, nil
}

func chooseMagic(random int32Random, pool []uint32) (int32, error) {
	value, err := random.nextInt32()
	if err != nil {
		return 0, err
	}
	if len(pool) == 0 {
		return value, nil
	}
	if value == math.MinInt32 {
		return int32(pool[0]), nil
	}
	index := int64(value)
	if index < 0 {
		index = -index
	}
	return int32(pool[index%int64(len(pool))]), nil
}

func encodeMOVRegister32(register uint8, immediate int32, mode64 bool) []byte {
	output := make([]byte, 0, 6)
	if mode64 && register >= 8 {
		output = append(output, 0x41)
	}
	output = append(output, 0xb8+(register&7), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(output[len(output)-4:], uint32(immediate))
	return output
}

func encodeADDRegister32(register uint8, immediate int32, mode64 bool) []byte {
	prefix := byte(0)
	if mode64 && register >= 8 {
		prefix = 0x41
	}
	// Iced's CodeAssembler selects the accumulator-special ADD EAX, imm32
	// form even when the immediate would fit in a sign-extended imm8.
	if register == 0 {
		output := []byte{0x05, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(output[1:], uint32(immediate))
		return output
	}
	if immediate >= math.MinInt8 && immediate <= math.MaxInt8 {
		output := make([]byte, 0, 4)
		if prefix != 0 {
			output = append(output, prefix)
		}
		output = append(output, 0x83, 0xc0|(register&7), byte(int8(immediate)))
		return output
	}
	output := make([]byte, 0, 7)
	if prefix != 0 {
		output = append(output, prefix)
	}
	output = append(output, 0x81, 0xc0|(register&7), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(output[len(output)-4:], uint32(immediate))
	return output
}

func encodePushRegister(register uint8, mode64 bool) []byte {
	if mode64 && register >= 8 {
		return []byte{0x41, 0x50 + (register & 7)}
	}
	return []byte{0x50 + (register & 7)}
}

func encodePopRegister(register uint8, mode64 bool) []byte {
	if mode64 && register >= 8 {
		return []byte{0x41, 0x58 + (register & 7)}
	}
	return []byte{0x58 + (register & 7)}
}

func encodeCMPRegisters(destination, source uint8, mode64 bool) []byte {
	output := make([]byte, 0, 3)
	if mode64 {
		rex := byte(0x40)
		if source >= 8 {
			rex |= 4
		}
		if destination >= 8 {
			rex |= 1
		}
		if rex != 0x40 {
			output = append(output, rex)
		}
	}
	output = append(output, 0x39, 0xc0|(source&7)<<3|(destination&7))
	return output
}

func encodeMOVMemoryRegister(memory stackMemory, source uint8, mode64 bool) ([]byte, error) {
	if memory.base != 4 && memory.base != 5 {
		return nil, fmt.Errorf("unsupported stack/base register %d", memory.base)
	}
	if memory.displace < math.MinInt32 || memory.displace > math.MaxInt32 {
		return nil, errors.New("memory displacement is outside disp32 range")
	}
	output := make([]byte, 0, 9)
	if memory.segment == 0x64 || memory.segment == 0x65 {
		output = append(output, memory.segment)
	}
	if mode64 && source >= 8 {
		output = append(output, 0x44) // REX.R
	}
	output = append(output, 0x89)
	displacement := int32(memory.displace)
	mod := byte(0)
	switch {
	case displacement == 0 && memory.base != 5:
		mod = 0
	case displacement >= math.MinInt8 && displacement <= math.MaxInt8:
		mod = 1
	default:
		mod = 2
	}
	output = append(output, mod<<6|(source&7)<<3|(memory.base&7))
	if memory.base == 4 {
		output = append(output, 0x24)
	}
	if mod == 1 {
		output = append(output, byte(int8(displacement)))
	} else if mod == 2 {
		var encoded [4]byte
		binary.LittleEndian.PutUint32(encoded[:], uint32(displacement))
		output = append(output, encoded[:]...)
	}
	return output, nil
}
