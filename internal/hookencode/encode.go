// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package hookencode

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func encodeAttach(object *coff.Object, state *analysis, ref relocationRef, instruction x86.Instruction, contextName, target string, wrapper *coff.Symbol) (Site, error) {
	relativeOffset, err := instructionRelativeOffset(instruction, ref.relocation.VirtualAddress)
	if err != nil {
		return Site{}, err
	}
	bytes := instruction.Bytes
	form := Form("")
	replacement := append([]byte(nil), bytes...)
	resultSymbol := wrapper.Name
	resultType := ref.relocation.Type
	resultAddend := uint32(0)

	if object.Machine == coff.MachineAMD64 {
		if ref.relocation.Type != coff.RelAMD64Rel32 {
			return Site{}, fmt.Errorf("%w: x64 import relocation type %#x", ErrUnsupportedForm, ref.relocation.Type)
		}
		switch {
		case len(bytes) == 6 && relativeOffset == 2 && bytes[0] == 0xff && bytes[1] == 0x15:
			form = FormCallIndirect64
			replacement = []byte{0x90, 0xe8, 0, 0, 0, 0}
		case len(bytes) == 6 && relativeOffset == 2 && bytes[0] == 0xff && bytes[1] == 0x25:
			form = FormJumpIndirect64
			replacement = []byte{0x90, 0xe9, 0, 0, 0, 0}
		case isRIPMove64(bytes, relativeOffset):
			form = FormMoveIndirect64
			replacement[1] = 0x8d // MOV reg,[IAT] -> LEA reg,[wrapper]
			zeroDWORD(replacement, relativeOffset)
		default:
			return Site{}, fmt.Errorf("%w: x64 attach expects FF/2, FF/4, or REX.W 8B RIP-relative", ErrUnsupportedForm)
		}
	} else {
		if ref.relocation.Type != coff.RelI386Dir32 {
			return Site{}, fmt.Errorf("%w: x86 import relocation type %#x", ErrUnsupportedForm, ref.relocation.Type)
		}
		resultSymbol = ".text"
		resultType = coff.RelI386Dir32
		resultAddend = wrapper.Value
		switch {
		case len(bytes) == 6 && relativeOffset == 2 && bytes[0] == 0xff && bytes[1] == 0x15:
			form = FormCallIndirect32
			replacement = []byte{0x90, 0xe8, 0, 0, 0, 0}
			resultSymbol = wrapper.Name
			resultType = coff.RelI386Rel32
			resultAddend = 0
		case len(bytes) == 6 && relativeOffset == 2 && bytes[0] == 0xff && bytes[1] == 0x25:
			form = FormJumpIndirect32
			replacement = []byte{0x90, 0xe9, 0, 0, 0, 0}
			resultSymbol = wrapper.Name
			resultType = coff.RelI386Rel32
			resultAddend = 0
		case len(bytes) == 5 && relativeOffset == 1 && bytes[0] == 0xa1:
			form = FormMoveEAXMoffs32
			replacement = []byte{0xb8, 0, 0, 0, 0}
			binary.LittleEndian.PutUint32(replacement[1:], wrapper.Value)
		case isAbsoluteMove32(bytes, relativeOffset):
			form = FormMoveIndirect32
			register := (bytes[1] >> 3) & 7
			replacement = []byte{0x90, 0xb8 + register, 0, 0, 0, 0}
			binary.LittleEndian.PutUint32(replacement[2:], wrapper.Value)
		default:
			return Site{}, fmt.Errorf("%w: x86 attach expects FF/2, FF/4, A1, or 8B absolute", ErrUnsupportedForm)
		}
	}

	site := relocatedSite(PassAttach, form, state, ref, instruction, contextName, target, wrapper.Name, replacement, resultSymbol, resultType, resultAddend)
	if isRelativeType(object.Machine, resultType) && resultSymbol == wrapper.Name {
		return resolveRelocatedSite(site, instruction, relativeOffset, wrapper.Value)
	}
	return site, nil
}

func encodeRelocatedRedirect(object *coff.Object, state *analysis, ref relocationRef, instruction x86.Instruction, contextName, target string, wrapper *coff.Symbol) (Site, error) {
	relativeOffset, err := instructionRelativeOffset(instruction, ref.relocation.VirtualAddress)
	if err != nil {
		return Site{}, err
	}
	bytes := instruction.Bytes
	replacement := append([]byte(nil), bytes...)
	form := Form("")
	resultSymbol := wrapper.Name
	resultType := ref.relocation.Type
	resultAddend := uint32(0)

	if isRelativeType(object.Machine, ref.relocation.Type) {
		switch {
		case len(bytes) == 5 && relativeOffset == 1 && bytes[0] == 0xe8:
			form = FormCallRel32
		case len(bytes) == 5 && relativeOffset == 1 && bytes[0] == 0xe9:
			form = FormJumpRel32
		case object.Machine == coff.MachineAMD64 && isRIPLEA64(bytes, relativeOffset):
			form = FormLEA64
		case object.Machine == coff.MachineAMD64 && isRIPMove64(bytes, relativeOffset):
			form = FormMoveIndirect64
		case object.Machine == coff.MachineAMD64 && len(bytes) == 6 && relativeOffset == 2 && bytes[0] == 0xff && bytes[1] == 0x15:
			form = FormCallIndirect64
		default:
			return Site{}, fmt.Errorf("%w: relocation-backed local reference is not a supported call, jump, LEA, or MOV", ErrUnsupportedForm)
		}
		zeroDWORD(replacement, relativeOffset)
		site := relocatedSite(PassRedirect, form, state, ref, instruction, contextName, target, wrapper.Name, replacement, resultSymbol, resultType, resultAddend)
		return resolveRelocatedSite(site, instruction, relativeOffset, wrapper.Value)
	}

	if object.Machine != coff.MachineI386 || ref.relocation.Type != coff.RelI386Dir32 || ref.relocation.SymbolName != ".text" {
		return Site{}, fmt.Errorf("%w: local absolute redirect requires x86 .text DIR32 relocation", ErrUnsupportedForm)
	}
	resultSymbol = ".text"
	resultType = coff.RelI386Dir32
	resultAddend = wrapper.Value
	switch {
	case len(bytes) == 5 && relativeOffset == 1 && bytes[0] >= 0xb8 && bytes[0] <= 0xbf:
		form = FormMoveImmediate32
		binary.LittleEndian.PutUint32(replacement[relativeOffset:], wrapper.Value)
	case len(bytes) == 6 && relativeOffset == 2 && bytes[0] == 0xc7 && bytes[1]&0xf8 == 0xc0:
		form = FormMoveImmediate32
		binary.LittleEndian.PutUint32(replacement[relativeOffset:], wrapper.Value)
	default:
		return Site{}, fmt.Errorf("%w: x86 local DIR32 redirect expects MOV r32, imm32", ErrUnsupportedForm)
	}
	return relocatedSite(PassRedirect, form, state, ref, instruction, contextName, target, wrapper.Name, replacement, resultSymbol, resultType, resultAddend), nil
}

func relocatedSite(pass Pass, form Form, state *analysis, ref relocationRef, instruction x86.Instruction, contextName, target, wrapper string, replacement []byte, resultSymbol string, resultType uint16, resultAddend uint32) Site {
	return Site{
		Pass: pass, Form: form,
		SectionIndex: state.sectionIndex, RelocationIndex: ref.index,
		SectionName: state.section.Name, RelocationOffset: ref.relocation.VirtualAddress,
		InstructionOffset: uint32(instruction.Address), InstructionLength: uint32(len(instruction.Bytes)),
		Context: contextName, Target: target, Wrapper: wrapper, Symbol: ref.relocation.SymbolName,
		Original: append([]byte(nil), instruction.Bytes...), Replacement: append([]byte(nil), replacement...),
		action: relocationRetarget, resultSymbol: resultSymbol, resultType: resultType,
		resultAddend: resultAddend, writeAddend: true,
		originalType: ref.relocation.Type, originalSymbol: ref.relocation.SymbolName,
	}
}

func resolveRelocatedSite(site Site, instruction x86.Instruction, relativeOffset int, target uint32) (Site, error) {
	replacement, err := retargetRelative(site.Replacement, relativeOffset, 4, instruction.Address, target)
	if err != nil {
		return Site{}, err
	}
	site.Replacement = replacement
	site.action = relocationConsume
	site.resultSymbol = ""
	site.resultType = 0
	site.resultAddend = 0
	site.writeAddend = false
	return site, nil
}

func classifyResolvedLocal(machine coff.Machine, instruction x86.Instruction) (Form, int64, int, int, bool) {
	bytes := instruction.Bytes
	start := int64(instruction.Address)
	end := start + int64(len(bytes))
	switch {
	case len(bytes) == 5 && bytes[0] == 0xe8:
		return FormCallRel32, end + int64(int32(binary.LittleEndian.Uint32(bytes[1:]))), 1, 4, true
	case len(bytes) == 5 && bytes[0] == 0xe9:
		return FormJumpRel32, end + int64(int32(binary.LittleEndian.Uint32(bytes[1:]))), 1, 4, true
	case len(bytes) == 2 && bytes[0] == 0xeb:
		return FormJumpRel8, end + int64(int8(bytes[1])), 1, 1, true
	}
	if machine != coff.MachineAMD64 {
		return "", 0, 0, 0, false
	}
	switch {
	case isRIPLEA64(bytes, 3):
		return FormLEA64, end + int64(int32(binary.LittleEndian.Uint32(bytes[3:]))), 3, 4, true
	case isRIPMove64(bytes, 3):
		return FormMoveIndirect64, end + int64(int32(binary.LittleEndian.Uint32(bytes[3:]))), 3, 4, true
	case len(bytes) == 6 && bytes[0] == 0xff && bytes[1] == 0x15:
		return FormCallIndirect64, end + int64(int32(binary.LittleEndian.Uint32(bytes[2:]))), 2, 4, true
	default:
		return "", 0, 0, 0, false
	}
}

func retargetRelative(original []byte, operandOffset, operandWidth int, instructionAddress uint64, target uint32) ([]byte, error) {
	if operandOffset < 0 || (operandWidth != 1 && operandWidth != 4) || operandOffset+operandWidth > len(original) {
		return nil, fmt.Errorf("%w: invalid relative operand bounds", ErrInvalidPlan)
	}
	end := int64(instructionAddress) + int64(len(original))
	delta := int64(target) - end
	replacement := append([]byte(nil), original...)
	if operandWidth == 1 {
		if delta < math.MinInt8 || delta > math.MaxInt8 {
			return nil, fmt.Errorf("%w: rel8 delta %d", ErrBranchRange, delta)
		}
		replacement[operandOffset] = byte(int8(delta))
		return replacement, nil
	}
	if delta < math.MinInt32 || delta > math.MaxInt32 {
		return nil, fmt.Errorf("%w: rel32 delta %d", ErrBranchRange, delta)
	}
	binary.LittleEndian.PutUint32(replacement[operandOffset:], uint32(int32(delta)))
	return replacement, nil
}

func instructionRelativeOffset(instruction x86.Instruction, relocationAddress uint32) (int, error) {
	if uint64(relocationAddress) < instruction.Address {
		return 0, fmt.Errorf("%w: relocation precedes decoded instruction", ErrInvalidPlan)
	}
	offset := uint64(relocationAddress) - instruction.Address
	if offset > uint64(len(instruction.Bytes)) || offset+4 > uint64(len(instruction.Bytes)) {
		return 0, fmt.Errorf("%w: relocation operand exceeds decoded instruction", ErrInvalidPlan)
	}
	return int(offset), nil
}

func isRIPMove64(bytes []byte, relocationOffset int) bool {
	return len(bytes) == 7 && relocationOffset == 3 && bytes[0] >= 0x48 && bytes[0] <= 0x4f && bytes[0]&0x08 != 0 && bytes[1] == 0x8b && bytes[2]&0xc7 == 0x05
}

func isRIPLEA64(bytes []byte, relocationOffset int) bool {
	return len(bytes) == 7 && relocationOffset == 3 && bytes[0] >= 0x48 && bytes[0] <= 0x4f && bytes[0]&0x08 != 0 && bytes[1] == 0x8d && bytes[2]&0xc7 == 0x05
}

func isAbsoluteMove32(bytes []byte, relocationOffset int) bool {
	return len(bytes) == 6 && relocationOffset == 2 && bytes[0] == 0x8b && bytes[1]&0xc7 == 0x05
}

func zeroDWORD(bytes []byte, offset int) {
	for index := 0; index < 4; index++ {
		bytes[offset+index] = 0
	}
}
