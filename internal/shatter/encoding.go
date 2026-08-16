// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package shatter

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

type memoryEncoding struct {
	rex         byte
	opcode      []byte
	hasModRM    bool
	mod         byte
	reg         byte
	rm          byte
	hasSIB      bool
	dispOffset  int
	dispSize    int
	tailOffset  int
	addressOver bool
}

func decodeRIPRelative(entry *instruction) (int, int64, error) {
	encoding, err := parseMemoryEncoding(entry.raw, coff.MachineAMD64)
	if err != nil {
		return 0, 0, fmt.Errorf("RIP-relative encoding is not provable: %w", err)
	}
	if encoding.addressOver || !encoding.hasModRM || encoding.mod != 0 || encoding.rm != 5 || encoding.hasSIB || encoding.dispSize != 4 {
		return 0, 0, errors.New("Capstone reports RIP-relative addressing but raw ModRM/disp32 does not prove it")
	}
	supported := false
	if len(encoding.opcode) == 1 && encoding.rex&8 != 0 {
		switch encoding.opcode[0] {
		case 0x8d: // LEA r64,m
			supported = entry.mnemonic == "lea"
		case 0x8b: // MOV r64,r/m64
			supported = entry.mnemonic == "mov"
		case 0xff: // CALL r/m64
			supported = entry.mnemonic == "call" && encoding.reg == 2
		}
	}
	// A near indirect call defaults to 64-bit operand size and need not carry
	// REX.W, unlike LEA and MOV.
	if len(encoding.opcode) == 1 && encoding.opcode[0] == 0xff && entry.mnemonic == "call" && encoding.reg == 2 {
		supported = true
	}
	if !supported {
		return 0, 0, errors.New("upstream LocalLabels supports only LEA r64,m, MOV r64,r/m64, and CALL r/m64 RIP-relative forms")
	}
	displacement := int64(int32(binary.LittleEndian.Uint32(entry.raw[encoding.dispOffset:encoding.tailOffset])))
	return encoding.dispOffset, int64(entry.oldEnd) + displacement, nil
}

func parseMemoryEncoding(raw []byte, machine coff.Machine) (memoryEncoding, error) {
	if len(raw) == 0 {
		return memoryEncoding{}, errors.New("empty instruction")
	}
	var result memoryEncoding
	position := 0
	for position < len(raw) && isLegacyPrefix(raw[position]) {
		if raw[position] == 0x67 {
			result.addressOver = true
		}
		position++
	}
	if machine == coff.MachineAMD64 {
		for position < len(raw) && raw[position] >= 0x40 && raw[position] <= 0x4f {
			if result.rex != 0 {
				return memoryEncoding{}, errors.New("multiple REX prefixes")
			}
			result.rex = raw[position]
			position++
		}
	}
	if position >= len(raw) {
		return memoryEncoding{}, errors.New("prefixes without opcode")
	}
	if isVEXOrEVEX(raw[position:], machine) {
		return memoryEncoding{}, errors.New("VEX/EVEX/XOP detail is unavailable")
	}
	first := raw[position]
	position++
	result.opcode = append(result.opcode, first)
	if first == 0x0f {
		if position >= len(raw) {
			return memoryEncoding{}, errors.New("truncated 0F opcode")
		}
		second := raw[position]
		position++
		result.opcode = append(result.opcode, second)
		if second == 0x38 || second == 0x3a {
			if position >= len(raw) {
				return memoryEncoding{}, errors.New("truncated three-byte opcode")
			}
			result.opcode = append(result.opcode, raw[position])
			position++
		}
	}
	result.hasModRM = opcodeHasModRM(result.opcode)
	if !result.hasModRM {
		result.tailOffset = position
		return result, nil
	}
	if position >= len(raw) {
		return memoryEncoding{}, errors.New("truncated ModRM")
	}
	modrm := raw[position]
	position++
	result.mod, result.reg, result.rm = modrm>>6, (modrm>>3)&7, modrm&7
	result.dispOffset = position
	if result.mod != 3 && result.rm == 4 {
		if position >= len(raw) {
			return memoryEncoding{}, errors.New("truncated SIB")
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
	result.tailOffset = result.dispOffset + result.dispSize
	if result.tailOffset > len(raw) {
		return memoryEncoding{}, errors.New("truncated displacement")
	}
	return result, nil
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

func opcodeHasModRM(opcode []byte) bool {
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
