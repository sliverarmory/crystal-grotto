// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package btf

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

type easyForm uint8

const (
	formInvalid easyForm = iota
	formAddressRegister
	formAddAccumulator
	formCompareAccumulator
	formLoad
	formLoadAddress
	formStoreOrFlags
	formConstantMemory
	formIndirectCall
	formImmediateToMemory
)

type memoryEncoding struct {
	modRMOffset int
	end         int
	dispOffset  int
	dispSize    int
	base        int
	index       int
	absolute    bool
	ripRelative bool
}

type easyEncoding struct {
	form       easyForm
	width      int
	reg        int
	opcodeAt   int
	opcodeSize int
	modRM      int
	immOffset  int
	immSize    int
	rexAt      int
	memory     memoryEncoding
	moffs      bool
}

type transformResult struct {
	bytes            []byte
	calls            []int
	relocationOffset int
}

type codeEmitter struct {
	bytes []byte
	calls []int
}

func (e *codeEmitter) add(values ...byte)   { e.bytes = append(e.bytes, values...) }
func (e *codeEmitter) append(values []byte) { e.bytes = append(e.bytes, values...) }
func (e *codeEmitter) call() {
	e.add(0xe8)
	e.calls = append(e.calls, len(e.bytes))
	e.add(0, 0, 0, 0)
}

func transformEasyPIC(plan *fixPlan, entry *fixInstruction, relocation *coff.Relocation) (transformResult, error) {
	relativeOffset := int(relocation.VirtualAddress - entry.oldStart)
	encoding, err := decodeEasyEncoding(entry.raw, relativeOffset, plan.pass)
	if err != nil {
		return transformResult{}, fmt.Errorf("btf: %s: unsupported instruction at %#x (%x): %w", plan.pass, entry.oldStart, entry.raw, err)
	}
	if err := validateRelocationType(plan.pass, relocation); err != nil {
		return transformResult{}, fmt.Errorf("btf: %s: instruction %#x: %w", plan.pass, entry.oldStart, err)
	}
	if encoding.form == formStoreOrFlags && encoding.width == 8 && encoding.reg >= 4 && encoding.rexAt < 0 {
		return transformResult{}, fmt.Errorf("btf: %s: instruction %#x uses a high-byte register operand", plan.pass, entry.oldStart)
	}
	if (encoding.form == formAddressRegister || encoding.form == formLoad || encoding.form == formLoadAddress || encoding.form == formStoreOrFlags) && encoding.reg == 4 {
		return transformResult{}, fmt.Errorf("btf: %s: instruction %#x uses the stack pointer as a rewritten value operand", plan.pass, entry.oldStart)
	}

	var addressOffset int32
	if plan.pass == passBSSX86 || plan.pass == passBSSX64 {
		remote, err := relocationRemoteOffset(plan.object, relocation)
		if err != nil {
			return transformResult{}, fmt.Errorf("btf: %s: relocation %#x: %w", plan.pass, relocation.VirtualAddress, err)
		}
		addressOffset = remote
		if plan.pass == passBSSX64 {
			adjustment := int32(len(entry.raw) - (relativeOffset + int(relocation.FromOffset())))
			addressOffset = int32(uint32(addressOffset) + uint32(adjustment))
		}
	}

	address := func(e *codeEmitter) (int, error) {
		switch plan.pass {
		case passX86References:
			return emitX86ReferenceAddress(e, entry.raw[relativeOffset:relativeOffset+4]), nil
		case passBSSX86:
			bss := findSection(plan.object, ".bss")
			if uint64(len(bss.Data)) > math.MaxInt32 {
				return -1, fmt.Errorf(".bss size %d exceeds signed 32-bit helper argument", len(bss.Data))
			}
			emitX86BSSAddress(e, int32(len(bss.Data)), addressOffset)
			return -1, nil
		case passBSSX64:
			bss := findSection(plan.object, ".bss")
			if uint64(len(bss.Data)) > math.MaxInt32 {
				return -1, fmt.Errorf(".bss size %d exceeds 32-bit helper argument", len(bss.Data))
			}
			shadow, err := x64ShadowSpace(plan, entry)
			if err != nil {
				return -1, err
			}
			emitX64BSSAddress(e, uint32(len(bss.Data)), addressOffset, shadow)
			return -1, nil
		default:
			return -1, fmt.Errorf("unknown pass")
		}
	}

	var output codeEmitter
	relocationInOutput := -1
	mode64 := plan.pass == passBSSX64
	accumulator := 0

	switch encoding.form {
	case formAddressRegister:
		if encoding.reg == accumulator {
			relocationInOutput, err = address(&output)
		} else {
			emitSaveAccumulator(&output, mode64)
			relocationInOutput, err = address(&output)
			emitMoveAccumulatorToRegister(&output, mode64, encoding.reg)
			emitRestoreAccumulator(&output, mode64)
		}

	case formAddAccumulator, formCompareAccumulator:
		if mode64 {
			return transformResult{}, fmt.Errorf("accumulator immediate form is x86-only")
		}
		output.add(0x51, 0x50) // push ecx; push eax
		relocationInOutput, err = address(&output)
		output.add(0x89, 0xc1, 0x58) // mov ecx,eax; pop eax
		if encoding.form == formAddAccumulator {
			output.add(0x01, 0xc8) // add eax,ecx
		} else {
			output.add(0x39, 0xc8) // cmp eax,ecx
		}
		output.add(0x59)

	case formLoad, formLoadAddress:
		if !mode64 && encoding.memory.base >= 0 {
			return transformX86BaseLoad(address, encoding, entry.raw)
		}
		if encoding.reg == accumulator {
			relocationInOutput, err = address(&output)
			if encoding.form == formLoad {
				output.append(patchMemoryToAccumulator(entry.raw, encoding, -1))
			}
		} else {
			emitSaveAccumulator(&output, mode64)
			relocationInOutput, err = address(&output)
			if encoding.form == formLoad {
				output.append(patchMemoryToAccumulator(entry.raw, encoding, -1))
			} else {
				emitMoveAccumulatorToRegister(&output, mode64, encoding.reg)
			}
			emitRestoreAccumulator(&output, mode64)
		}

	case formStoreOrFlags:
		if encoding.reg == accumulator {
			emitPushRegister(&output, mode64, accumulator)
			emitPushRegister(&output, mode64, 3) // ebx/rbx temporary
			emitMoveRegister(&output, mode64, encoding.width, 3, accumulator)
			relocationInOutput, err = address(&output)
			output.append(patchMemoryToAccumulator(entry.raw, encoding, 3))
			emitPopRegister(&output, mode64, 3)
			emitPopRegister(&output, mode64, accumulator)
		} else {
			emitSaveAccumulator(&output, mode64)
			relocationInOutput, err = address(&output)
			output.append(patchMemoryToAccumulator(entry.raw, encoding, -1))
			emitRestoreAccumulator(&output, mode64)
		}

	case formConstantMemory:
		emitSaveAccumulator(&output, mode64)
		relocationInOutput, err = address(&output)
		output.append(patchMemoryToAccumulator(entry.raw, encoding, -1))
		emitRestoreAccumulator(&output, mode64)

	case formIndirectCall:
		relocationInOutput, err = address(&output)
		if mode64 {
			output.add(0x48, 0x8b, 0x00, 0xff, 0xd0)
		} else {
			output.add(0x8b, 0x00, 0xff, 0xd0)
		}

	case formImmediateToMemory:
		if mode64 {
			return transformResult{}, fmt.Errorf("x64 immediate-to-non-RIP memory is unsupported")
		}
		if encoding.memory.index >= 0 || encoding.memory.base == 4 {
			return transformResult{}, fmt.Errorf("x86 immediate address store with index/ESP base is unsupported")
		}
		if encoding.memory.base == accumulator {
			output.add(0x51, 0x50)
			relocationInOutput, err = address(&output)
			output.add(0x89, 0xc1, 0x58)
			output.append(convertImmediateStore(entry.raw, encoding, 1))
			output.add(0x59)
		} else {
			output.add(0x50)
			relocationInOutput, err = address(&output)
			output.append(convertImmediateStore(entry.raw, encoding, 0))
			output.add(0x58)
		}

	default:
		return transformResult{}, fmt.Errorf("btf: %s: instruction %#x has no safe transform", plan.pass, entry.oldStart)
	}
	if err != nil {
		return transformResult{}, fmt.Errorf("btf: %s: instruction %#x: %w", plan.pass, entry.oldStart, err)
	}
	if len(output.bytes) == 0 {
		return transformResult{}, fmt.Errorf("btf: %s: instruction %#x produced no code", plan.pass, entry.oldStart)
	}
	return transformResult{bytes: output.bytes, calls: output.calls, relocationOffset: relocationInOutput}, nil
}

func relocationRemoteOffset(object *coff.Object, relocation *coff.Relocation) (int32, error) {
	if relocation == nil {
		return 0, fmt.Errorf("nil relocation")
	}
	symbol := relocation.Symbol
	if symbol == nil {
		name := relocationName(relocation)
		for _, candidate := range object.Symbols {
			if candidate != nil && candidate.Name == name {
				if symbol != nil {
					return 0, fmt.Errorf("symbol %q is duplicated", name)
				}
				symbol = candidate
			}
		}
	}
	if symbol == nil {
		return 0, fmt.Errorf("relocation references missing symbol %q", relocationName(relocation))
	}
	section := relocation.Section
	if section == nil {
		section = findSection(object, ".text")
	}
	if section == nil || uint64(relocation.VirtualAddress)+4 > uint64(len(section.Data)) {
		return 0, fmt.Errorf("relocation at %#x is outside .text", relocation.VirtualAddress)
	}
	offset := int32(binary.LittleEndian.Uint32(section.Data[relocation.VirtualAddress : relocation.VirtualAddress+4]))
	// Crystal Palace performs this addition in Java int arithmetic.
	return int32(uint32(offset) + symbol.Value), nil
}

func validateRelocationType(pass fixPass, relocation *coff.Relocation) error {
	switch pass {
	case passX86References, passBSSX86:
		if relocation.Type != coff.RelI386Dir32 {
			return fmt.Errorf("relocation type %#x is not IMAGE_REL_I386_DIR32", relocation.Type)
		}
	case passBSSX64:
		if relocation.Type < coff.RelAMD64Rel32 || relocation.Type > coff.RelAMD64Rel32_5 {
			return fmt.Errorf("relocation type %#x is not IMAGE_REL_AMD64_REL32[_1..5]", relocation.Type)
		}
	}
	return nil
}

func emitX86ReferenceAddress(e *codeEmitter, addend []byte) int {
	e.add(0x51, 0x52) // push ecx; push edx
	e.call()
	e.add(0xb9)
	relocationOffset := len(e.bytes)
	e.append(addend)
	e.add(0x83, 0xc1, 0x05, 0x01, 0xc8, 0x5a, 0x59)
	return relocationOffset
}

func emitX86BSSAddress(e *codeEmitter, size, offset int32) {
	e.add(0x51, 0x52)
	emitPushImmediate32(e, size)
	e.call()
	e.add(0x83, 0xc4, 0x04, 0x5a, 0x59)
	emitAddAccumulatorImmediate(e, false, offset)
}

func emitX64BSSAddress(e *codeEmitter, size uint32, offset int32, shadow byte) {
	e.add(0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53)
	e.add(0x48, 0x83, 0xec, shadow)
	e.add(0xb9)
	var value [4]byte
	binary.LittleEndian.PutUint32(value[:], size)
	e.append(value[:])
	e.call()
	e.add(0x48, 0x83, 0xc4, shadow)
	e.add(0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5a, 0x59)
	emitAddAccumulatorImmediate(e, true, offset)
}

func emitPushImmediate32(e *codeEmitter, value int32) {
	if value >= math.MinInt8 && value <= math.MaxInt8 {
		e.add(0x6a, byte(int8(value)))
		return
	}
	e.add(0x68)
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], uint32(value))
	e.append(encoded[:])
}

func emitAddAccumulatorImmediate(e *codeEmitter, mode64 bool, value int32) {
	if value == 0 {
		return
	}
	if mode64 {
		e.add(0x48)
	}
	if value >= math.MinInt8 && value <= math.MaxInt8 {
		e.add(0x83, 0xc0, byte(int8(value)))
		return
	}
	e.add(0x05)
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], uint32(value))
	e.append(encoded[:])
}

func emitSaveAccumulator(e *codeEmitter, mode64 bool) {
	e.add(0x50)
	if mode64 {
		e.add(0x50) // upstream pushrax preserves 16-byte stack alignment
	}
}

func emitRestoreAccumulator(e *codeEmitter, mode64 bool) {
	e.add(0x58)
	if mode64 {
		e.add(0x58)
	}
}

func emitPushRegister(e *codeEmitter, mode64 bool, register int) {
	if mode64 && register >= 8 {
		e.add(0x41)
	}
	e.add(byte(0x50 + register&7))
}

func emitPopRegister(e *codeEmitter, mode64 bool, register int) {
	if mode64 && register >= 8 {
		e.add(0x41)
	}
	e.add(byte(0x58 + register&7))
}

func emitMoveAccumulatorToRegister(e *codeEmitter, mode64 bool, destination int) {
	if mode64 {
		rex := byte(0x48)
		if destination >= 8 {
			rex |= 0x01
		}
		e.add(rex)
	}
	e.add(0x89, byte(0xc0|destination&7))
}

func emitMoveRegister(e *codeEmitter, mode64 bool, width, destination, source int) {
	if width == 16 {
		e.add(0x66)
	}
	if mode64 {
		rex := byte(0x40)
		if width == 64 {
			rex |= 0x08
		}
		if source >= 8 {
			rex |= 0x04
		}
		if destination >= 8 {
			rex |= 0x01
		}
		if rex != 0x40 || width == 8 && (destination >= 4 || source >= 4) {
			e.add(rex)
		}
	}
	opcode := byte(0x89)
	if width == 8 {
		opcode = 0x88
	}
	e.add(opcode, byte(0xc0|(source&7)<<3|destination&7))
}

func transformX86BaseLoad(address func(*codeEmitter) (int, error), encoding easyEncoding, raw []byte) (transformResult, error) {
	if encoding.memory.index >= 0 || encoding.memory.base == 4 || encoding.memory.base == 5 {
		return transformResult{}, fmt.Errorf("btf: x86 base-relative transform rejects index/ESP/EBP addressing")
	}
	var output codeEmitter
	// Reserve a stable stack slot for the original base register before the
	// helper saves or clobbers volatile registers.
	output.add(0x83, 0xec, 0x04)
	output.add(0x89, byte(0x04|(encoding.memory.base&7)<<3), 0x24) // mov [esp],base
	relocationOffset := -1
	var err error
	if encoding.reg == 0 {
		relocationOffset, err = address(&output)
		output.add(0x03, 0x04, 0x24) // add eax,[esp]
		if encoding.form == formLoad {
			output.append(patchMemoryToAccumulator(raw, encoding, -1))
		}
	} else {
		output.add(0x50)
		relocationOffset, err = address(&output)
		output.add(0x03, 0x44, 0x24, 0x04) // add eax,[esp+4]
		if encoding.form == formLoad {
			output.append(patchMemoryToAccumulator(raw, encoding, -1))
		} else {
			emitMoveAccumulatorToRegister(&output, false, encoding.reg)
		}
		output.add(0x58)
	}
	output.add(0x83, 0xc4, 0x04)
	if err != nil {
		return transformResult{}, err
	}
	return transformResult{bytes: output.bytes, calls: output.calls, relocationOffset: relocationOffset}, nil
}

func patchMemoryToAccumulator(raw []byte, encoding easyEncoding, replacementReg int) []byte {
	if encoding.moffs {
		var result []byte
		if encoding.width == 16 {
			result = append(result, 0x66)
		}
		switch encoding.form {
		case formLoad:
			result = append(result, 0x8b, byte(replacementModRMReg(encoding, replacementReg)<<3))
		default:
			opcode := byte(0x89)
			if encoding.width == 8 {
				opcode = 0x88
			}
			reg := encoding.reg
			if replacementReg >= 0 {
				reg = replacementReg
			}
			result = append(result, opcode, byte((reg&7)<<3))
		}
		return result
	}
	result := append([]byte(nil), raw[:encoding.memory.modRMOffset]...)
	if encoding.rexAt >= 0 && encoding.rexAt < len(result) {
		result[encoding.rexAt] &^= 0x03 // [rax], never [r8] and no index
	}
	modRM := raw[encoding.memory.modRMOffset] & 0x38
	if replacementReg >= 0 {
		modRM = byte((replacementReg & 7) << 3)
		if encoding.rexAt >= 0 && encoding.rexAt < len(result) {
			result[encoding.rexAt] &^= 0x04
		}
	}
	result = append(result, modRM)
	result = append(result, raw[encoding.memory.end:]...)
	return result
}

func replacementModRMReg(encoding easyEncoding, replacement int) int {
	if replacement >= 0 {
		return replacement
	}
	return encoding.reg
}

func convertImmediateStore(raw []byte, encoding easyEncoding, source int) []byte {
	result := append([]byte(nil), raw[:encoding.immOffset]...)
	result[encoding.opcodeAt] = 0x89
	result[encoding.memory.modRMOffset] = (result[encoding.memory.modRMOffset] & 0xc7) | byte((source&7)<<3)
	return result
}

func decodeEasyEncoding(raw []byte, relocationOffset int, pass fixPass) (easyEncoding, error) {
	if relocationOffset < 0 || relocationOffset+4 > len(raw) {
		return easyEncoding{}, fmt.Errorf("relocation is not a four-byte instruction field")
	}
	mode64 := pass == passBSSX64
	result := easyEncoding{reg: -1, rexAt: -1, memory: memoryEncoding{base: -1, index: -1, dispOffset: -1}}
	position := 0
	operand16 := false
	addressOverride := false
	rexSeen := false
	for position < len(raw) {
		value := raw[position]
		switch value {
		case 0x66:
			if rexSeen {
				return easyEncoding{}, fmt.Errorf("legacy prefix follows REX prefix")
			}
			operand16 = true
			position++
		case 0x67:
			if rexSeen {
				return easyEncoding{}, fmt.Errorf("legacy prefix follows REX prefix")
			}
			addressOverride = true
			position++
		case 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65:
			if rexSeen {
				return easyEncoding{}, fmt.Errorf("legacy prefix follows REX prefix")
			}
			position++
		default:
			if mode64 && value >= 0x40 && value <= 0x4f {
				if rexSeen {
					return easyEncoding{}, fmt.Errorf("multiple REX prefixes")
				}
				rexSeen = true
				result.rexAt = position
				position++
				continue
			}
			goto prefixesDone
		}
	}
prefixesDone:
	if position >= len(raw) || addressOverride {
		return easyEncoding{}, fmt.Errorf("missing opcode or address-size override")
	}
	result.opcodeAt = position
	opcode := raw[position]
	position++
	second := byte(0)
	result.opcodeSize = 1
	if opcode == 0x0f {
		if position >= len(raw) {
			return easyEncoding{}, fmt.Errorf("truncated two-byte opcode")
		}
		second = raw[position]
		position++
		result.opcodeSize = 2
	}
	rex := byte(0)
	if result.rexAt >= 0 {
		rex = raw[result.rexAt]
	}
	width := 32
	if operand16 {
		width = 16
	}
	if mode64 && rex&8 != 0 {
		width = 64
	}
	result.width = width

	if opcode >= 0xb8 && opcode <= 0xbf && !mode64 {
		result.form = formAddressRegister
		result.reg = int(opcode - 0xb8)
		result.immOffset = position
		result.immSize = len(raw) - position
		if width != 32 || result.immSize != 4 || relocationOffset != result.immOffset {
			return easyEncoding{}, fmt.Errorf("MOV register relocation is not imm32")
		}
		return result, nil
	}
	if !mode64 && (opcode == 0x05 || opcode == 0x3d) {
		result.form = formAddAccumulator
		if opcode == 0x3d {
			result.form = formCompareAccumulator
		}
		result.reg = 0
		result.immOffset = position
		if width != 32 || len(raw)-position != 4 || relocationOffset != position {
			return easyEncoding{}, fmt.Errorf("accumulator relocation is not imm32")
		}
		return result, nil
	}
	if !mode64 && opcode >= 0xa0 && opcode <= 0xa3 {
		if len(raw)-position != 4 || relocationOffset != position {
			return easyEncoding{}, fmt.Errorf("moffs relocation is not a 32-bit address")
		}
		result.moffs = true
		result.reg = 0
		result.memory = memoryEncoding{modRMOffset: -1, end: len(raw), dispOffset: position, dispSize: 4, absolute: true, base: -1, index: -1}
		switch opcode {
		case 0xa0:
			result.form, result.width = formLoad, 8
		case 0xa1:
			result.form = formLoad
		case 0xa2:
			result.form, result.width = formStoreOrFlags, 8
		case 0xa3:
			result.form = formStoreOrFlags
		}
		return result, nil
	}

	needsModRM := opcode == 0x8b || opcode == 0x8d || opcode == 0x88 || opcode == 0x89 || opcode == 0x38 || opcode == 0x39 || opcode == 0x3a || opcode == 0x3b || opcode == 0x84 || opcode == 0x85 || opcode == 0x80 || opcode == 0x81 || opcode == 0x83 || opcode == 0xf6 || opcode == 0xf7 || opcode == 0xc6 || opcode == 0xc7 || opcode == 0xff || opcode == 0x0f && (second == 0xb6 || second == 0xb7 || second == 0xbe || second == 0xbf)
	if !needsModRM || position >= len(raw) {
		return easyEncoding{}, fmt.Errorf("opcode is not an upstream easy-PIC form")
	}
	result.modRM = position
	memory, err := parseMemory(raw, position, mode64)
	if err != nil {
		return easyEncoding{}, err
	}
	result.memory = memory
	modRM := raw[position]
	reg := int(modRM>>3) & 7
	if mode64 && rex&4 != 0 {
		reg += 8
	}
	result.reg = reg
	position = memory.end

	switch {
	case opcode == 0x8d:
		result.form = formLoadAddress
		if mode64 && width != 64 || !mode64 && width != 32 {
			return easyEncoding{}, fmt.Errorf("LEA operand width %d is not supported by the upstream pass", width)
		}
	case opcode == 0x8b:
		result.form = formLoad
		if width != 32 && !(mode64 && width == 64) {
			return easyEncoding{}, fmt.Errorf("MOV load width %d is not supported by the upstream pass", width)
		}
	case opcode == 0x0f && (second == 0xb6 || second == 0xbe):
		if mode64 && rex&8 != 0 {
			return easyEncoding{}, fmt.Errorf("64-bit MOVZX/MOVSX destination is not supported by the upstream pass")
		}
		result.form, result.width = formLoad, 8
	case opcode == 0x0f && (second == 0xb7 || second == 0xbf):
		if mode64 && rex&8 != 0 {
			return easyEncoding{}, fmt.Errorf("64-bit MOVZX/MOVSX destination is not supported by the upstream pass")
		}
		result.form, result.width = formLoad, 16
	case opcode == 0x88 || opcode == 0x38 || opcode == 0x3a || opcode == 0x84:
		result.form, result.width = formStoreOrFlags, 8
	case opcode == 0x89 || opcode == 0x39 || opcode == 0x3b || opcode == 0x85:
		result.form = formStoreOrFlags
	case opcode == 0xff && reg&7 == 2:
		result.form = formIndirectCall
		result.width = 64
		if !mode64 {
			result.width = 32
		}
	case opcode == 0x80 || opcode == 0x81 || opcode == 0x83 || opcode == 0xf6 || opcode == 0xf7 || opcode == 0xc6 || opcode == 0xc7:
		group := int(modRM>>3) & 7
		valid := opcode == 0x80 && group == 7 || (opcode == 0x81 || opcode == 0x83) && group == 7 || (opcode == 0xf6 || opcode == 0xf7) && group == 0 || (opcode == 0xc6 || opcode == 0xc7) && group == 0
		if !valid {
			return easyEncoding{}, fmt.Errorf("unsupported opcode extension /%d", group)
		}
		if opcode == 0x80 || opcode == 0xf6 || opcode == 0xc6 {
			result.width = 8
		}
		result.immOffset = position
		result.immSize = len(raw) - position
		expectedImmediate := 0
		switch opcode {
		case 0x80, 0x83, 0xf6, 0xc6:
			expectedImmediate = 1
		case 0x81, 0xf7:
			expectedImmediate = 4
			if result.width == 16 {
				expectedImmediate = 2
			}
		case 0xc7:
			expectedImmediate = 4
			if result.width == 16 {
				expectedImmediate = 2
			}
		}
		if result.immSize != expectedImmediate {
			return easyEncoding{}, fmt.Errorf("immediate is %d bytes; want %d", result.immSize, expectedImmediate)
		}
		if (opcode == 0xc7 || opcode == 0xc6) && relocationOffset == result.immOffset {
			if mode64 || result.width != 32 || result.immSize != 4 || memory.base < 0 {
				return easyEncoding{}, fmt.Errorf("immediate-address store has unsupported operands")
			}
			result.form = formImmediateToMemory
			return result, nil
		}
		result.form = formConstantMemory
	default:
		return easyEncoding{}, fmt.Errorf("unrecognized easy-PIC opcode")
	}

	if mode64 {
		if !memory.ripRelative {
			return easyEncoding{}, fmt.Errorf("x64 memory operand is not RIP-relative")
		}
	} else if result.form == formLoadAddress && memory.base < 0 {
		return easyEncoding{}, fmt.Errorf("x86 LEA form requires a base register")
	} else if !memory.absolute && !(result.form == formLoad || result.form == formLoadAddress) {
		return easyEncoding{}, fmt.Errorf("x86 form requires an absolute memory operand")
	}
	if relocationOffset != memory.dispOffset || memory.dispSize != 4 {
		return easyEncoding{}, fmt.Errorf("relocation does not select the memory disp32")
	}
	return result, nil
}

func parseMemory(raw []byte, modRMOffset int, mode64 bool) (memoryEncoding, error) {
	result := memoryEncoding{modRMOffset: modRMOffset, base: -1, index: -1, dispOffset: -1}
	if modRMOffset >= len(raw) {
		return result, fmt.Errorf("missing ModRM")
	}
	modRM := raw[modRMOffset]
	mod, rm := int(modRM>>6), int(modRM&7)
	if mod == 3 {
		return result, fmt.Errorf("relocated operand is a register")
	}
	position := modRMOffset + 1
	if rm == 4 {
		if position >= len(raw) {
			return result, fmt.Errorf("truncated SIB")
		}
		sib := raw[position]
		position++
		index := int(sib>>3) & 7
		base := int(sib & 7)
		if index != 4 {
			result.index = index
		}
		if mod == 0 && base == 5 {
			result.absolute = !mode64
		} else {
			result.base = base
		}
	} else if mod == 0 && rm == 5 {
		result.ripRelative = mode64
		result.absolute = !mode64
	} else {
		result.base = rm
	}
	switch mod {
	case 0:
		if result.absolute || result.ripRelative || rm == 4 && result.base < 0 {
			result.dispOffset, result.dispSize = position, 4
			position += 4
		}
	case 1:
		result.dispOffset, result.dispSize = position, 1
		position++
	case 2:
		result.dispOffset, result.dispSize = position, 4
		position += 4
	}
	if position > len(raw) {
		return result, fmt.Errorf("truncated memory displacement")
	}
	result.end = position
	return result, nil
}

func x64ShadowSpace(plan *fixPlan, entry *fixInstruction) (byte, error) {
	function := containingFunction(plan.object, entry.oldStart)
	if function == nil {
		return 0, fmt.Errorf("cannot determine containing function for x64 stack alignment")
	}
	// Windows x64 entry RSP is 8 mod 16. Follow the straight-line prefix to the
	// target, accepting only stack operations whose exact delta is encoded here.
	mod := 8
	for _, candidate := range plan.instructions {
		if candidate.oldStart < function.Value || candidate.oldStart >= entry.oldStart {
			continue
		}
		delta, known, control := stackDelta64(candidate.raw)
		if control || strings.HasPrefix(candidate.mnemonic, "j") || strings.HasPrefix(candidate.mnemonic, "loop") {
			return 0, fmt.Errorf("cannot prove x64 stack alignment across control flow at %#x", candidate.oldStart)
		}
		if !known {
			operands := strings.TrimSpace(candidate.operands)
			if candidate.mnemonic == "push" || candidate.mnemonic == "pop" || operands == "rsp" || strings.HasPrefix(operands, "rsp,") {
				return 0, fmt.Errorf("cannot prove x64 stack adjustment at %#x (%s %s)", candidate.oldStart, candidate.mnemonic, candidate.operands)
			}
			continue
		}
		mod = (mod + delta) & 15
	}
	if mod == 0 {
		return 0x20, nil
	}
	if mod == 8 {
		return 0x28, nil
	}
	return 0, fmt.Errorf("unsupported x64 RSP alignment %d at %#x", mod, entry.oldStart)
}

func stackDelta64(raw []byte) (delta int, known, control bool) {
	if _, _, relative := relativeField(raw); relative && raw[0] != 0xe8 {
		return 0, true, true
	}
	position := 0
	for position < len(raw) && raw[position] >= 0x40 && raw[position] <= 0x4f {
		position++
	}
	if position >= len(raw) {
		return 0, false, false
	}
	opcode := raw[position]
	if opcode >= 0x50 && opcode <= 0x57 {
		return 8, true, false
	}
	if opcode >= 0x58 && opcode <= 0x5f {
		return -8, true, false
	}
	if len(raw) >= 4 && raw[0] == 0x48 && raw[1] == 0x83 && raw[2] == 0xec {
		return int(raw[3]), true, false
	}
	if len(raw) >= 4 && raw[0] == 0x48 && raw[1] == 0x83 && raw[2] == 0xc4 {
		return -int(raw[3]), true, false
	}
	if len(raw) >= 7 && raw[0] == 0x48 && raw[1] == 0x81 && raw[2] == 0xec {
		return int(binary.LittleEndian.Uint32(raw[3:7])), true, false
	}
	if len(raw) >= 7 && raw[0] == 0x48 && raw[1] == 0x81 && raw[2] == 0xc4 {
		return -int(binary.LittleEndian.Uint32(raw[3:7])), true, false
	}
	return 0, false, false
}

// A retained relocation generated by emitX86ReferenceAddress always points to
// `mov ecx, imm32` inside this exact helper envelope. Recognizing the envelope
// prevents a second fixptrs command from recursively rewriting its own output.
func generatedX86ReferenceAt(text []byte, instruction *fixInstruction) bool {
	if instruction == nil || len(instruction.raw) != 5 || instruction.raw[0] != 0xb9 || instruction.oldStart < 7 || uint64(instruction.oldEnd)+7 > uint64(len(text)) {
		return false
	}
	start := int(instruction.oldStart)
	before := text[start-7 : start]
	after := text[instruction.oldEnd : instruction.oldEnd+7]
	return before[0] == 0x51 && before[1] == 0x52 && before[2] == 0xe8 &&
		string(after) == string([]byte{0x83, 0xc1, 0x05, 0x01, 0xc8, 0x5a, 0x59})
}
