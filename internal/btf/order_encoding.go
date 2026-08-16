// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package btf

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

type orderRelative struct {
	offset int
	size   int
}

func decodeOrderRelative(raw []byte) (orderRelative, bool) {
	switch {
	case len(raw) == 5 && (raw[0] == 0xe8 || raw[0] == 0xe9):
		return orderRelative{offset: 1, size: 4}, true
	case len(raw) == 2 && (raw[0] == 0xeb || raw[0] >= 0x70 && raw[0] <= 0x7f || raw[0] >= 0xe0 && raw[0] <= 0xe3):
		return orderRelative{offset: 1, size: 1}, true
	case len(raw) == 6 && raw[0] == 0x0f && raw[1] >= 0x80 && raw[1] <= 0x8f:
		return orderRelative{offset: 2, size: 4}, true
	default:
		return orderRelative{}, false
	}
}

func orderRelativeTarget(instruction *decodedOrderInstruction, reference orderRelative) (int64, error) {
	if reference.offset < 0 || reference.size <= 0 || reference.offset+reference.size > len(instruction.raw) {
		return 0, errors.New("malformed relative instruction")
	}
	var displacement int64
	if reference.size == 1 {
		displacement = int64(int8(instruction.raw[reference.offset]))
	} else {
		displacement = int64(int32(binary.LittleEndian.Uint32(instruction.raw[reference.offset : reference.offset+4])))
	}
	return int64(instruction.end) + displacement, nil
}

func isUnprovenOrderControlFlow(instruction *decodedOrderInstruction) bool {
	if instruction == nil {
		return false
	}
	name := instruction.mnemonic
	if name == "xbegin" || name == "ljmp" || name == "lcall" {
		return true
	}
	if name == "ret" || name == "retf" || name == "iret" || strings.HasPrefix(name, "iret") {
		return false
	}
	if name != "call" && name != "jmp" && !strings.HasPrefix(name, "j") && !strings.HasPrefix(name, "loop") {
		return false
	}
	return !isOrderIndirectControlFlow(instruction)
}

func isOrderIndirectControlFlow(instruction *decodedOrderInstruction) bool {
	if instruction == nil || (instruction.mnemonic != "call" && instruction.mnemonic != "jmp") {
		return false
	}
	position := skipOrderPrefixes(instruction.raw)
	if position+2 > len(instruction.raw) || instruction.raw[position] != 0xff {
		return false
	}
	operation := (instruction.raw[position+1] >> 3) & 7
	return operation == 2 || operation == 4
}

func decodeOrderRIPRelative(instruction *decodedOrderInstruction) (int, int64, error) {
	encoding, err := parseOrderMemoryEncoding(instruction.raw, coff.MachineAMD64)
	if err != nil {
		return 0, 0, err
	}
	if encoding.addressOver || !encoding.hasModRM || encoding.mod != 0 || encoding.rm != 5 || encoding.hasSIB || encoding.dispSize != 4 {
		return 0, 0, errors.New("Capstone reports RIP-relative addressing but raw ModRM/disp32 does not prove it")
	}
	if instruction.mnemonic == "call" || instruction.mnemonic == "jmp" {
		if len(encoding.opcode) != 1 || encoding.opcode[0] != 0xff {
			return 0, 0, errors.New("RIP-relative control flow is not a proven FF /2 or FF /4 form")
		}
		want := byte(2)
		if instruction.mnemonic == "jmp" {
			want = 4
		}
		if encoding.reg != want {
			return 0, 0, errors.New("RIP-relative control-flow ModRM operation does not match its mnemonic")
		}
	}
	displacement := int64(int32(binary.LittleEndian.Uint32(instruction.raw[encoding.dispOffset : encoding.dispOffset+4])))
	return encoding.dispOffset, int64(instruction.end) + displacement, nil
}

type orderMemoryEncoding struct {
	opcode      []byte
	hasModRM    bool
	mod         byte
	reg         byte
	rm          byte
	hasSIB      bool
	dispOffset  int
	dispSize    int
	addressOver bool
}

func parseOrderMemoryEncoding(raw []byte, machine coff.Machine) (orderMemoryEncoding, error) {
	if len(raw) == 0 {
		return orderMemoryEncoding{}, errors.New("empty instruction")
	}
	var result orderMemoryEncoding
	position := 0
	for position < len(raw) && isOrderLegacyPrefix(raw[position]) {
		if raw[position] == 0x67 {
			result.addressOver = true
		}
		position++
	}
	if machine == coff.MachineAMD64 {
		seenREX := false
		for position < len(raw) && raw[position] >= 0x40 && raw[position] <= 0x4f {
			if seenREX {
				return orderMemoryEncoding{}, errors.New("multiple REX prefixes")
			}
			seenREX = true
			position++
		}
	}
	if position >= len(raw) {
		return orderMemoryEncoding{}, errors.New("prefixes without opcode")
	}
	if isOrderVectorPrefix(raw[position:], machine) {
		return orderMemoryEncoding{}, errors.New("VEX/EVEX/XOP detail is unavailable")
	}
	first := raw[position]
	position++
	result.opcode = append(result.opcode, first)
	if first == 0x0f {
		if position >= len(raw) {
			return orderMemoryEncoding{}, errors.New("truncated 0F opcode")
		}
		second := raw[position]
		position++
		result.opcode = append(result.opcode, second)
		if second == 0x38 || second == 0x3a {
			if position >= len(raw) {
				return orderMemoryEncoding{}, errors.New("truncated three-byte opcode")
			}
			result.opcode = append(result.opcode, raw[position])
			position++
		}
	}
	result.hasModRM = orderOpcodeHasModRM(result.opcode)
	if !result.hasModRM {
		return result, nil
	}
	if position >= len(raw) {
		return orderMemoryEncoding{}, errors.New("truncated ModRM")
	}
	modrm := raw[position]
	position++
	result.mod, result.reg, result.rm = modrm>>6, (modrm>>3)&7, modrm&7
	result.dispOffset = position
	if result.mod != 3 && result.rm == 4 {
		if position >= len(raw) {
			return orderMemoryEncoding{}, errors.New("truncated SIB")
		}
		result.hasSIB = true
		sib := raw[position]
		position++
		result.dispOffset = position
		if result.mod == 0 && sib&7 == 5 {
			result.dispSize = 4
		}
	}
	if result.mod != 3 && !result.hasSIB {
		switch result.mod {
		case 0:
			if result.rm == 5 {
				result.dispSize = 4
			}
		case 1:
			result.dispSize = 1
		case 2:
			result.dispSize = 4
		}
	} else if result.mod == 1 {
		result.dispSize = 1
	} else if result.mod == 2 {
		result.dispSize = 4
	}
	if result.dispOffset+result.dispSize > len(raw) {
		return orderMemoryEncoding{}, errors.New("truncated displacement")
	}
	return result, nil
}

func orderOpcodeHasModRM(opcode []byte) bool {
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

func isOrderVectorPrefix(raw []byte, machine coff.Machine) bool {
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

func skipOrderPrefixes(raw []byte) int {
	position := 0
	for position < len(raw) && isOrderLegacyPrefix(raw[position]) {
		position++
	}
	for position < len(raw) && raw[position] >= 0x40 && raw[position] <= 0x4f {
		position++
	}
	return position
}

func isOrderLegacyPrefix(value byte) bool {
	switch value {
	case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3:
		return true
	default:
		return false
	}
}

func hasOrderWord(value, word string) bool {
	for _, field := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
	}) {
		if field == word {
			return true
		}
	}
	return false
}
