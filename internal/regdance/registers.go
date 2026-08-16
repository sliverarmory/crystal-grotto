// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package regdance

import (
	"strings"
	"unicode"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

// upstreamRegisterOrder is Java HashSet iteration order for Iced
// AsmRegister64 values at HashMap's default capacity. Iced hashes a register
// as registerID*397; the eight relevant hashes occupy distinct buckets.
var upstreamRegisterOrder = []Register{RBP, R15, R14, RBX, R13, RDI, R12, RSI}

var registerNames = map[string]registerUse{
	"rbx": {RBX, 64, false}, "ebx": {RBX, 32, false}, "bx": {RBX, 16, false}, "bl": {RBX, 8, false}, "bh": {RBX, 8, true},
	"rbp": {RBP, 64, false}, "ebp": {RBP, 32, false}, "bp": {RBP, 16, false}, "bpl": {RBP, 8, false},
	"rsi": {RSI, 64, false}, "esi": {RSI, 32, false}, "si": {RSI, 16, false}, "sil": {RSI, 8, false},
	"rdi": {RDI, 64, false}, "edi": {RDI, 32, false}, "di": {RDI, 16, false}, "dil": {RDI, 8, false},
	"r12": {R12, 64, false}, "r12d": {R12, 32, false}, "r12w": {R12, 16, false}, "r12b": {R12, 8, false},
	"r13": {R13, 64, false}, "r13d": {R13, 32, false}, "r13w": {R13, 16, false}, "r13b": {R13, 8, false},
	"r14": {R14, 64, false}, "r14d": {R14, 32, false}, "r14w": {R14, 16, false}, "r14b": {R14, 8, false},
	"r15": {R15, 64, false}, "r15d": {R15, 32, false}, "r15w": {R15, 16, false}, "r15b": {R15, 8, false},
}

type registerUse struct {
	base Register
	size int
	high bool
}

func nativeRegisters(machine coff.Machine) map[Register]struct{} {
	result := map[Register]struct{}{RBX: {}, RBP: {}, RSI: {}, RDI: {}}
	if machine == coff.MachineAMD64 {
		result[R12] = struct{}{}
		result[R13] = struct{}{}
		result[R14] = struct{}{}
		result[R15] = struct{}{}
	}
	return result
}

func orderedRegisters(set map[Register]struct{}) []Register {
	result := make([]Register, 0, len(set))
	for _, register := range upstreamRegisterOrder {
		if _, ok := set[register]; ok {
			result = append(result, register)
		}
	}
	return result
}

func registerName(register Register, size int) (string, bool) {
	switch size {
	case 64:
		return register.String(), true
	case 32:
		switch register {
		case RBX:
			return "ebx", true
		case RBP:
			return "ebp", true
		case RSI:
			return "esi", true
		case RDI:
			return "edi", true
		default:
			return register.String() + "d", register >= R12 && register <= R15
		}
	case 16:
		switch register {
		case RBX:
			return "bx", true
		case RBP:
			return "bp", true
		case RSI:
			return "si", true
		case RDI:
			return "di", true
		default:
			return register.String() + "w", register >= R12 && register <= R15
		}
	case 8:
		switch register {
		case RBX:
			return "bl", true
		case RBP:
			return "bpl", true
		case RSI:
			return "sil", true
		case RDI:
			return "dil", true
		default:
			return register.String() + "b", register >= R12 && register <= R15
		}
	default:
		return "", false
	}
}

func words(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_')
	})
}

func explicitRegisterUses(operands string) []registerUse {
	var result []registerUse
	for _, word := range words(operands) {
		if use, ok := registerNames[word]; ok {
			result = append(result, use)
		}
	}
	return result
}

func hasRegisterName(operands, name string) bool {
	name = strings.ToLower(name)
	for _, word := range words(operands) {
		if word == name {
			return true
		}
	}
	return false
}

func replaceRegisters(operands string, mapping map[Register]Register) (string, bool) {
	lower := strings.ToLower(operands)
	var output strings.Builder
	changed := false
	for index := 0; index < len(lower); {
		if isWordByte(lower[index]) {
			end := index + 1
			for end < len(lower) && isWordByte(lower[end]) {
				end++
			}
			word := lower[index:end]
			if use, ok := registerNames[word]; ok && !use.high {
				if target, mapped := mapping[use.base]; mapped {
					if replacement, valid := registerName(target, use.size); valid {
						output.WriteString(replacement)
						changed = changed || replacement != word
						index = end
						continue
					}
				}
			}
			output.WriteString(word)
			index = end
			continue
		}
		output.WriteByte(lower[index])
		index++
	}
	return output.String(), changed
}

func isWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '_'
}
