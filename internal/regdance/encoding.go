// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package regdance

import (
	"errors"
	"fmt"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

type fieldKind uint8

const (
	fieldOpcode fieldKind = iota
	fieldModRMReg
	fieldModRMRM
	fieldMemoryBase
	fieldMemoryIndex
)

type registerField struct {
	kind fieldKind
	old  Register
}

type instructionEncoding struct {
	raw             []byte
	machine         coff.Machine
	legacyEnd       int
	rex             byte
	opcodeStart     int
	opcodeEnd       int
	opcode          []byte
	hasModRM        bool
	modRMOffset     int
	mod             byte
	reg             byte
	rm              byte
	hasSIB          bool
	sibOffset       int
	scale           byte
	index           byte
	base            byte
	dispOffset      int
	dispSize        int
	tailOffset      int
	address16       bool
	addressOverride bool
	embeddedReg     bool
	embeddedByte    int
}

func parseInstructionEncoding(raw []byte, machine coff.Machine) (instructionEncoding, error) {
	if len(raw) == 0 {
		return instructionEncoding{}, errors.New("empty instruction")
	}
	result := instructionEncoding{raw: raw, machine: machine}
	position := 0
	addressPrefix := false
	for position < len(raw) && isLegacyPrefix(raw[position]) {
		if raw[position] == 0x67 {
			addressPrefix = true
		}
		position++
	}
	result.legacyEnd = position
	result.address16 = machine == coff.MachineI386 && addressPrefix
	result.addressOverride = addressPrefix
	if machine == coff.MachineAMD64 {
		for position < len(raw) && raw[position] >= 0x40 && raw[position] <= 0x4f {
			if result.rex != 0 {
				return instructionEncoding{}, errors.New("multiple REX prefixes require Iced re-encoding")
			}
			result.rex = raw[position]
			position++
		}
	}
	if position >= len(raw) {
		return instructionEncoding{}, errors.New("instruction contains prefixes only")
	}
	result.opcodeStart = position
	first := raw[position]
	if isVEXOrEVEX(raw[position:], machine) {
		return instructionEncoding{}, errors.New("VEX/EVEX/XOP operand detail is unavailable")
	}
	position++
	result.opcode = append(result.opcode, first)
	if first == 0x0f {
		if position >= len(raw) {
			return instructionEncoding{}, errors.New("truncated 0F opcode")
		}
		second := raw[position]
		position++
		result.opcode = append(result.opcode, second)
		if second == 0x38 || second == 0x3a {
			if position >= len(raw) {
				return instructionEncoding{}, errors.New("truncated three-byte opcode")
			}
			result.opcode = append(result.opcode, raw[position])
			position++
		}
	}
	result.opcodeEnd = position
	result.embeddedReg, result.embeddedByte = embeddedRegisterOpcode(result.opcode, machine)
	result.hasModRM = opcodeHasModRM(result.opcode, machine)
	if !result.hasModRM {
		result.tailOffset = position
		return result, nil
	}
	if position >= len(raw) {
		return instructionEncoding{}, errors.New("truncated ModRM byte")
	}
	result.modRMOffset = position
	modRM := raw[position]
	position++
	result.mod, result.reg, result.rm = modRM>>6, (modRM>>3)&7, modRM&7
	result.dispOffset = position
	if result.mod != 3 && !result.address16 && result.rm == 4 {
		if position >= len(raw) {
			return instructionEncoding{}, errors.New("truncated SIB byte")
		}
		result.hasSIB = true
		result.sibOffset = position
		sib := raw[position]
		position++
		result.scale, result.index, result.base = sib>>6, (sib>>3)&7, sib&7
		result.dispOffset = position
	}
	if result.mod != 3 {
		switch result.mod {
		case 0:
			if result.address16 {
				if result.rm == 6 {
					result.dispSize = 2
				}
			} else if result.hasSIB {
				if result.base == 5 {
					result.dispSize = 4
				}
			} else if result.rm == 5 {
				result.dispSize = 4
			}
		case 1:
			result.dispSize = 1
		case 2:
			if result.address16 {
				result.dispSize = 2
			} else {
				result.dispSize = 4
			}
		}
	}
	result.tailOffset = result.dispOffset + result.dispSize
	if result.tailOffset > len(raw) {
		return instructionEncoding{}, errors.New("truncated displacement")
	}
	return result, nil
}

func isLegacyPrefix(value byte) bool {
	switch value {
	case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3:
		return true
	default:
		return false
	}
}

func isVEXOrEVEX(raw []byte, machine coff.Machine) bool {
	if len(raw) == 0 {
		return false
	}
	switch raw[0] {
	case 0x62:
		return machine == coff.MachineAMD64
	case 0xc4, 0xc5:
		return machine == coff.MachineAMD64 || len(raw) > 1 && raw[1]&0xc0 == 0xc0
	case 0x8f:
		return len(raw) > 1 && raw[1]&0x1f >= 8
	default:
		return false
	}
}

func embeddedRegisterOpcode(opcode []byte, machine coff.Machine) (bool, int) {
	if len(opcode) == 1 {
		value := opcode[0]
		if value >= 0x50 && value <= 0x5f || value >= 0x90 && value <= 0x97 || value >= 0xb0 && value <= 0xbf {
			return true, 0
		}
		if machine == coff.MachineI386 && value >= 0x40 && value <= 0x4f {
			return true, 0
		}
	}
	if len(opcode) == 2 && opcode[0] == 0x0f && opcode[1] >= 0xc8 && opcode[1] <= 0xcf {
		return true, 1
	}
	return false, 0
}

func opcodeHasModRM(opcode []byte, machine coff.Machine) bool {
	if len(opcode) == 0 {
		return false
	}
	if len(opcode) >= 3 {
		return true
	}
	if len(opcode) == 2 {
		second := opcode[1]
		switch second {
		case 0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0e,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37, 0x77,
			0xa0, 0xa1, 0xa2, 0xa8, 0xa9, 0xaa:
			return false
		}
		if second >= 0x80 && second <= 0x8f || second >= 0xc8 && second <= 0xcf {
			return false
		}
		return true
	}
	value := opcode[0]
	if value <= 0x3f {
		return value&7 <= 3
	}
	if value == 0x62 || value == 0x63 || value == 0x69 || value == 0x6b {
		return true
	}
	if value >= 0x80 && value <= 0x8f {
		return true
	}
	if value == 0xc0 || value == 0xc1 || value == 0xc4 || value == 0xc5 || value == 0xc6 || value == 0xc7 {
		return true
	}
	if value >= 0xd0 && value <= 0xd3 || value >= 0xd8 && value <= 0xdf {
		return true
	}
	return value == 0xf6 || value == 0xf7 || value == 0xfe || value == 0xff
}

func (e instructionEncoding) candidateFields(mapping map[Register]Register) []registerField {
	var fields []registerField
	appendField := func(kind fieldKind, number byte) {
		register := Register(number)
		if _, ok := mapping[register]; ok {
			fields = append(fields, registerField{kind: kind, old: register})
		}
	}
	if e.embeddedReg {
		number := e.opcode[e.embeddedByte]&7 | (e.rex&1)<<3
		appendField(fieldOpcode, number)
	}
	if !e.hasModRM {
		return fields
	}
	appendField(fieldModRMReg, e.reg|((e.rex>>2)&1)<<3)
	if e.mod == 3 {
		appendField(fieldModRMRM, e.rm|(e.rex&1)<<3)
		return fields
	}
	if e.address16 {
		return fields
	}
	if e.hasSIB {
		if !(e.mod == 0 && e.base == 5) {
			appendField(fieldMemoryBase, e.base|(e.rex&1)<<3)
		}
		if !(e.index == 4 && e.rex&2 == 0) {
			appendField(fieldMemoryIndex, e.index|((e.rex>>1)&1)<<3)
		}
	} else if !(e.mod == 0 && e.rm == 5) {
		appendField(fieldMemoryBase, e.rm|(e.rex&1)<<3)
	}
	return fields
}

func (e instructionEncoding) rewrite(fields []registerField, selected uint, mapping map[Register]Register, expectedOperands string) ([]byte, error) {
	if len(fields) > 8 {
		return nil, errors.New("too many ambiguous register fields")
	}
	selectedKind := make(map[fieldKind]Register, len(fields))
	for index, field := range fields {
		if selected&(1<<index) == 0 {
			continue
		}
		target, ok := mapping[field.old]
		if !ok {
			return nil, errors.New("selected register has no mapping")
		}
		selectedKind[field.kind] = target
	}

	opcode := append([]byte(nil), e.opcode...)
	rexBits := e.rex & 0x0f
	setREX := func(mask byte, register Register) {
		rexBits &^= mask
		if register >= 8 {
			rexBits |= mask
		}
	}
	if target, ok := selectedKind[fieldOpcode]; ok {
		opcode[e.embeddedByte] = opcode[e.embeddedByte]&^7 | byte(target)&7
		setREX(1, target)
	}

	output := make([]byte, 0, len(e.raw)+2)
	output = append(output, e.raw[:e.legacyEnd]...)
	reg := e.reg
	if target, ok := selectedKind[fieldModRMReg]; ok {
		reg = byte(target) & 7
		setREX(4, target)
	}
	rm := e.rm
	if target, ok := selectedKind[fieldModRMRM]; ok {
		rm = byte(target) & 7
		setREX(1, target)
	}

	var addressing []byte
	if e.hasModRM && e.mod != 3 {
		if e.address16 {
			if _, base := selectedKind[fieldMemoryBase]; base {
				return nil, errors.New("16-bit addressing requires Iced operand detail")
			}
			if _, index := selectedKind[fieldMemoryIndex]; index {
				return nil, errors.New("16-bit addressing requires Iced operand detail")
			}
			addressing = append(addressing, byte(e.mod<<6)|reg<<3|rm)
			addressing = append(addressing, e.raw[e.dispOffset:e.tailOffset]...)
		} else {
			base, basePresent := e.memoryBase()
			index, indexPresent := e.memoryIndex()
			if target, ok := selectedKind[fieldMemoryBase]; ok {
				base, basePresent = target, true
			}
			if target, ok := selectedKind[fieldMemoryIndex]; ok {
				index, indexPresent = target, true
			}
			if basePresent {
				setREX(1, base)
			}
			if indexPresent {
				setREX(2, index)
			}
			displacement := append([]byte(nil), e.raw[e.dispOffset:e.tailOffset]...)
			dispSize := len(displacement)
			mod := e.mod
			if !basePresent {
				mod = 0
				if dispSize != 4 {
					return nil, errors.New("base-less address does not carry disp32")
				}
			} else if dispSize == 0 {
				if byte(base)&7 == 5 {
					mod = 1
					displacement = []byte{0}
				} else {
					mod = 0
				}
			} else if dispSize == 1 {
				mod = 1
			} else if dispSize == 4 {
				mod = 2
			} else {
				return nil, fmt.Errorf("unsupported displacement width %d", dispSize)
			}
			needsSIB := indexPresent || basePresent && byte(base)&7 == 4
			if needsSIB {
				addressing = append(addressing, byte(mod<<6)|reg<<3|4)
				indexBits := byte(4)
				if indexPresent {
					indexBits = byte(index) & 7
				}
				baseBits := byte(5)
				if basePresent {
					baseBits = byte(base) & 7
				}
				addressing = append(addressing, e.scale<<6|indexBits<<3|baseBits)
			} else {
				rmBits := byte(5)
				if basePresent {
					rmBits = byte(base) & 7
				}
				addressing = append(addressing, byte(mod<<6)|reg<<3|rmBits)
			}
			addressing = append(addressing, displacement...)
		}
	}

	needBareREX := needsBareREX(expectedOperands)
	if e.machine == coff.MachineAMD64 && (rexBits != 0 || needBareREX) {
		output = append(output, 0x40|rexBits)
	}
	output = append(output, opcode...)
	if e.hasModRM {
		if e.mod == 3 {
			output = append(output, byte(3<<6)|reg<<3|rm)
			output = append(output, e.raw[e.modRMOffset+1:]...)
		} else {
			output = append(output, addressing...)
			output = append(output, e.raw[e.tailOffset:]...)
		}
	} else {
		output = append(output, e.raw[e.opcodeEnd:]...)
	}
	return output, nil
}

func (e instructionEncoding) memoryBase() (Register, bool) {
	if !e.hasModRM || e.mod == 3 || e.address16 {
		return 0, false
	}
	if e.hasSIB {
		if e.mod == 0 && e.base == 5 {
			return 0, false
		}
		return Register(e.base | (e.rex&1)<<3), true
	}
	if e.mod == 0 && e.rm == 5 {
		return 0, false
	}
	return Register(e.rm | (e.rex&1)<<3), true
}

func (e instructionEncoding) memoryIndex() (Register, bool) {
	if !e.hasSIB || e.address16 || e.mod == 3 || e.index == 4 && e.rex&2 == 0 {
		return 0, false
	}
	return Register(e.index | ((e.rex>>1)&1)<<3), true
}

func needsBareREX(operands string) bool {
	for _, word := range words(operands) {
		switch word {
		case "spl", "bpl", "sil", "dil":
			return true
		}
	}
	return false
}

func normalizeOperands(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(value)), " ")
}
