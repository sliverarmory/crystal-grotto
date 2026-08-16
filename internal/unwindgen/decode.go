// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package unwindgen

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

type instructionKind uint8

const (
	kindOther instructionKind = iota
	kindPush
	kindPop
	kindSubRSP
	kindAddRSP
	kindFrameMOV
	kindFrameLEA
	kindCall
	kindReturn
	kindJumpRCX
	kindStackDynamic
)

type instructionDetail struct {
	instruction x86.Instruction
	kind        instructionKind
	register    uint8
	amount      uint32
	frameOffset uint32
}

type prefixState struct {
	opcode int
	rexW   bool
	rexR   bool
	rexX   bool
	rexB   bool
}

func classifyInstruction(function string, instruction x86.Instruction) (instructionDetail, error) {
	detail := instructionDetail{instruction: instruction}
	raw := instruction.Bytes
	if len(raw) == 0 {
		return detail, unsupported(function, instruction, "decoded instruction has no bytes")
	}
	mnemonic := strings.ToLower(strings.TrimSpace(instruction.Mnemonic))
	prefix := parsePrefixes(raw)
	if prefix.opcode >= len(raw) {
		return detail, unsupported(function, instruction, "instruction consists only of prefixes")
	}
	opcode := raw[prefix.opcode]
	remainder := raw[prefix.opcode:]

	if opcode >= 0x50 && opcode <= 0x57 && len(remainder) == 1 {
		if mnemonic != "push" {
			return detail, unsupported(function, instruction, "PUSH opcode has inconsistent decoder metadata")
		}
		detail.kind = kindPush
		detail.register = uint8(opcode - 0x50)
		if prefix.rexB {
			detail.register += 8
		}
		if strings.ToLower(strings.TrimSpace(instruction.Operands)) != registerName(detail.register) {
			return detail, unsupported(function, instruction, "PUSH operand is not the encoded x64 register")
		}
		return detail, nil
	}
	if opcode >= 0x58 && opcode <= 0x5f && len(remainder) == 1 {
		if mnemonic != "pop" {
			return detail, unsupported(function, instruction, "POP opcode has inconsistent decoder metadata")
		}
		detail.kind = kindPop
		detail.register = uint8(opcode - 0x58)
		if prefix.rexB {
			detail.register += 8
		}
		if strings.ToLower(strings.TrimSpace(instruction.Operands)) != registerName(detail.register) {
			return detail, unsupported(function, instruction, "POP operand is not the encoded x64 register")
		}
		return detail, nil
	}
	if strings.HasPrefix(mnemonic, "push") || strings.HasPrefix(mnemonic, "pop") {
		return detail, unsupported(function, instruction, "PUSH/POP form is not a provable x64 general-register operation")
	}

	if opcode == 0x83 || opcode == 0x81 {
		if parsed, ok, err := parseStackImmediate(function, instruction, prefix); ok || err != nil {
			return parsed, err
		}
	}
	if (mnemonic == "sub" || mnemonic == "add") && firstOperand(instruction.Operands) == "rsp" {
		return detail, unsupported(function, instruction, "RSP adjustment is not SUB/ADD rsp, imm8/imm32")
	}

	if opcode == 0x89 && prefix.rexW && len(remainder) == 2 {
		modRM := remainder[1]
		if modRM>>6 == 3 {
			source := uint8((modRM >> 3) & 7)
			if prefix.rexR {
				source += 8
			}
			destination := uint8(modRM & 7)
			if prefix.rexB {
				destination += 8
			}
			if source == 4 {
				if mnemonic != "mov" {
					return detail, unsupported(function, instruction, "frame-pointer MOV has inconsistent decoder metadata")
				}
				operands := splitOperands(instruction.Operands)
				if len(operands) != 2 || operands[0] != registerName(destination) || operands[1] != "rsp" {
					return detail, unsupported(function, instruction, "frame-pointer MOV operands do not match the encoded x64 registers")
				}
				detail.kind = kindFrameMOV
				detail.register = destination
				return detail, nil
			}
			if destination == 4 {
				// A register-based restoration of RSP is provably dynamic. It is
				// valid only when the prologue established a frame pointer.
				detail.kind = kindStackDynamic
				return detail, nil
			}
		}
	}

	if opcode == 0x8d && prefix.rexW {
		parsed, ok, err := parseLEA(function, instruction, prefix)
		if ok || err != nil {
			return parsed, err
		}
	}
	if mnemonic == "lea" && (firstOperand(instruction.Operands) == "rsp" || strings.Contains(strings.ToLower(instruction.Operands), "rsp")) {
		return detail, unsupported(function, instruction, "RSP/frame-pointer LEA has an unsupported addressing form")
	}

	if mnemonic == "call" {
		detail.kind = kindCall
		return detail, nil
	}
	if mnemonic == "ret" {
		if (opcode == 0xc3 && len(remainder) == 1) || (opcode == 0xc2 && len(remainder) == 3) {
			detail.kind = kindReturn
			return detail, nil
		}
		return detail, unsupported(function, instruction, "RET form is not a provable near x64 return")
	}
	if strings.HasPrefix(mnemonic, "ret") || strings.HasPrefix(mnemonic, "iret") {
		return detail, unsupported(function, instruction, "return form lacks provable near x64 stack semantics")
	}
	if mnemonic == "jmp" && opcode == 0xff && len(remainder) == 2 {
		modRM := remainder[1]
		register := uint8(modRM & 7)
		if prefix.rexB {
			register += 8
		}
		if modRM>>6 == 3 && (modRM>>3)&7 == 4 && register == 1 {
			if strings.ToLower(strings.TrimSpace(instruction.Operands)) != "rcx" {
				return detail, unsupported(function, instruction, "JMP rcx opcode has inconsistent decoder metadata")
			}
			detail.kind = kindJumpRCX
			return detail, nil
		}
	}
	operands := splitOperands(instruction.Operands)
	if mnemonic == "leave" || mnemonic == "enter" || len(operands) > 0 && isStackPointerRegister(operands[0]) {
		detail.kind = kindStackDynamic
		return detail, nil
	}
	if len(operands) > 1 {
		for _, operand := range operands[1:] {
			if isStackPointerRegister(operand) {
				return detail, unsupported(function, instruction, "bare stack-pointer operand lacks provable write semantics without Iced detail")
			}
		}
	}
	return detail, nil
}

func parseStackImmediate(function string, instruction x86.Instruction, prefix prefixState) (instructionDetail, bool, error) {
	detail := instructionDetail{instruction: instruction}
	raw := instruction.Bytes
	remainder := raw[prefix.opcode:]
	if !prefix.rexW || len(remainder) < 3 {
		return detail, false, nil
	}
	opcode, modRM := remainder[0], remainder[1]
	if modRM>>6 != 3 || modRM&7 != 4 || prefix.rexB || prefix.rexR {
		return detail, false, nil
	}
	operation := (modRM >> 3) & 7
	if operation != 0 && operation != 5 {
		return detail, false, nil
	}
	mnemonic := strings.ToLower(strings.TrimSpace(instruction.Mnemonic))
	detail.kind = kindAddRSP
	want := "add"
	if operation == 5 {
		detail.kind = kindSubRSP
		want = "sub"
	}
	if mnemonic != want {
		return detail, true, unsupported(function, instruction, "RSP immediate opcode has inconsistent decoder metadata")
	}
	if firstOperand(instruction.Operands) != "rsp" {
		return detail, true, unsupported(function, instruction, "RSP immediate operands do not match the encoded x64 register")
	}
	var signed int64
	switch opcode {
	case 0x83:
		if len(remainder) != 3 {
			return detail, true, unsupported(function, instruction, "RSP imm8 adjustment has an invalid length")
		}
		signed = int64(int8(remainder[2]))
	case 0x81:
		if len(remainder) != 6 {
			return detail, true, unsupported(function, instruction, "RSP imm32 adjustment has an invalid length")
		}
		signed = int64(int32(binary.LittleEndian.Uint32(remainder[2:])))
	default:
		return detail, false, nil
	}
	if signed <= 0 {
		return detail, true, unsupported(function, instruction, "RSP adjustment is not a positive stack size")
	}
	detail.amount = uint32(signed)
	return detail, true, nil
}

func parseLEA(function string, instruction x86.Instruction, prefix prefixState) (instructionDetail, bool, error) {
	detail := instructionDetail{instruction: instruction}
	raw := instruction.Bytes
	remainder := raw[prefix.opcode:]
	if len(remainder) < 3 || remainder[0] != 0x8d {
		return detail, false, nil
	}
	modRM := remainder[1]
	mod := modRM >> 6
	destination := uint8((modRM >> 3) & 7)
	if prefix.rexR {
		destination += 8
	}
	if mod == 3 || modRM&7 != 4 || prefix.rexB {
		return detail, false, nil
	}
	sib := remainder[2]
	if (sib>>3)&7 != 4 || prefix.rexX || sib&7 != 4 {
		return detail, false, nil
	}
	displacementAt := 3
	var displacement int64
	switch mod {
	case 0:
		if len(remainder) != displacementAt {
			return detail, true, unsupported(function, instruction, "RSP LEA has trailing bytes")
		}
	case 1:
		if len(remainder) != displacementAt+1 {
			return detail, true, unsupported(function, instruction, "RSP LEA disp8 has an invalid length")
		}
		displacement = int64(int8(remainder[displacementAt]))
	case 2:
		if len(remainder) != displacementAt+4 {
			return detail, true, unsupported(function, instruction, "RSP LEA disp32 has an invalid length")
		}
		displacement = int64(int32(binary.LittleEndian.Uint32(remainder[displacementAt:])))
	}
	if destination == 4 {
		detail.kind = kindStackDynamic
		return detail, true, nil
	}
	if strings.ToLower(strings.TrimSpace(instruction.Mnemonic)) != "lea" {
		return detail, true, unsupported(function, instruction, "frame-pointer LEA has inconsistent decoder metadata")
	}
	operands := splitOperands(instruction.Operands)
	if len(operands) != 2 || operands[0] != registerName(destination) || !strings.Contains(operands[1], "rsp") {
		return detail, true, unsupported(function, instruction, "frame-pointer LEA operands do not match the encoded x64 registers")
	}
	if displacement < 0 || displacement > 240 || displacement%16 != 0 {
		return detail, true, unsupported(function, instruction, "frame-pointer offset is not an encodable non-negative multiple of 16")
	}
	detail.kind = kindFrameLEA
	detail.register = destination
	detail.frameOffset = uint32(displacement)
	return detail, true, nil
}

func parsePrefixes(raw []byte) prefixState {
	var result prefixState
	for result.opcode < len(raw) {
		next := raw[result.opcode]
		switch next {
		case 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67:
			result.opcode++
			continue
		}
		if next >= 0x40 && next <= 0x4f {
			result.rexW = next&8 != 0
			result.rexR = next&4 != 0
			result.rexX = next&2 != 0
			result.rexB = next&1 != 0
			result.opcode++
			continue
		}
		break
	}
	return result
}

func firstOperand(operands string) string {
	if comma := strings.IndexByte(operands, ','); comma >= 0 {
		operands = operands[:comma]
	}
	return strings.ToLower(strings.TrimSpace(operands))
}

func splitOperands(operands string) []string {
	if strings.TrimSpace(operands) == "" {
		return nil
	}
	parts := strings.Split(operands, ",")
	for index := range parts {
		parts[index] = strings.ToLower(strings.TrimSpace(parts[index]))
	}
	return parts
}

func isStackPointerRegister(operand string) bool {
	switch operand {
	case "rsp", "esp", "sp", "spl":
		return true
	default:
		return false
	}
}

func registerName(register uint8) string {
	registers := [...]string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
	if int(register) >= len(registers) {
		return ""
	}
	return registers[register]
}

func unsupported(function string, instruction x86.Instruction, reason string) *UnsupportedError {
	offset := uint32(0)
	if instruction.Address <= uint64(^uint32(0)) {
		offset = uint32(instruction.Address)
	}
	return &UnsupportedError{
		Function: function, Offset: offset, Instruction: instruction.Assembly(), Reason: reason,
	}
}

func (d instructionDetail) String() string {
	return fmt.Sprintf("%s at %#x", d.instruction.Assembly(), d.instruction.Address)
}
