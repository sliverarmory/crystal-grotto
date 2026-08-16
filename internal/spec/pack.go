// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package spec

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf16"
)

func pack(format, arch string, args []string, env Environment) ([]byte, error) {
	result := make([]byte, 0)
	argIndex := 0
	prependLength := false
	for index := 0; index < len(format); {
		template := format[index]
		index++
		switch template {
		case ' ':
			continue
		case '#':
			prependLength = true
			continue
		case '@':
			if index >= len(format) {
				return nil, fmt.Errorf("pack: @ character is missing alignment argument (e.g., @4, @8, @n)")
			}
			alignment := 0
			switch format[index] {
			case 'n':
				if arch == "x64" {
					alignment = 8
				} else {
					alignment = 4
				}
			case '4':
				alignment = 4
			case '8':
				alignment = 8
			default:
				return nil, fmt.Errorf("pack: invalid alignment '@%c'. Use @4, @8, or @n", format[index])
			}
			index++
			if remainder := len(result) % alignment; remainder != 0 {
				result = append(result, make([]byte, alignment-remainder)...)
			}
			prependLength = false
			continue
		}

		var value []byte
		if template == 'x' {
			value = []byte{0}
		} else {
			if !strings.ContainsRune("ab h l i s p v w z Z", rune(template)) || template == ' ' {
				return nil, fmt.Errorf("pack: unknown template %c at position %d", template, index-1)
			}
			if argIndex >= len(args) {
				return nil, fmt.Errorf("pack: no argument for %c at position %d", template, index-1)
			}
			arg := args[argIndex]
			argIndex++
			var err error
			value, err = packValue(template, arch, arg, env)
			if err != nil {
				return nil, err
			}
		}
		if prependLength {
			var length [4]byte
			binary.LittleEndian.PutUint32(length[:], uint32(len(value)))
			result = append(result, length[:]...)
			prependLength = false
		}
		result = append(result, value...)
	}
	if argIndex < len(args) {
		return nil, fmt.Errorf("pack: format string %s only consumed %d of %d arguments", format, argIndex, len(args))
	}
	return result, nil
}

func packValue(template byte, arch, arg string, env Environment) ([]byte, error) {
	switch template {
	case 'h':
		cleaned := strings.ReplaceAll(arg, " ", "")
		if len(cleaned)%2 != 0 {
			return nil, fmt.Errorf("String length not divisible by 2")
		}
		value, err := hex.DecodeString(cleaned)
		if err != nil {
			return nil, err
		}
		return value, nil
	case 'b':
		value, err := decodeInteger(arg, 8)
		return []byte{byte(value)}, err
	case 's':
		value, err := decodeInteger(arg, 16)
		if err != nil {
			return nil, err
		}
		result := make([]byte, 2)
		binary.LittleEndian.PutUint16(result, uint16(value))
		return result, nil
	case 'i':
		value, err := decodeInteger(arg, 32)
		if err != nil {
			return nil, err
		}
		result := make([]byte, 4)
		binary.LittleEndian.PutUint32(result, uint32(value))
		return result, nil
	case 'l':
		value, err := decodeInteger(arg, 64)
		if err != nil {
			return nil, err
		}
		result := make([]byte, 8)
		binary.LittleEndian.PutUint64(result, value)
		return result, nil
	case 'p':
		if arch == "x64" {
			return packValue('l', arch, arg, env)
		}
		return packValue('i', arch, arg, env)
	case 'v':
		return env.Bytes(arg)
	case 'a':
		return []byte(arg), nil
	case 'w':
		return utf16LE(arg, false), nil
	case 'z':
		return append([]byte(arg), 0), nil
	case 'Z':
		return utf16LE(arg, true), nil
	default:
		return nil, fmt.Errorf("pack: unimplemented templated char %c", template)
	}
}

func decodeInteger(original string, bits int) (uint64, error) {
	value := original
	negative := false
	if strings.HasPrefix(value, "-") {
		negative = true
		value = strings.TrimPrefix(value, "-")
	} else {
		value = strings.TrimPrefix(value, "+")
	}
	radix := 10
	switch {
	case strings.HasPrefix(value, "0x"):
		radix, value = 16, value[2:]
	case strings.HasPrefix(value, "0") && len(value) > 1:
		radix, value = 8, value[1:]
	case strings.HasPrefix(value, "#"):
		radix, value = 16, value[1:]
	}
	number := new(big.Int)
	if _, ok := number.SetString(value, radix); !ok {
		return 0, fmt.Errorf("Can't decode %s as base %d number", original, radix)
	}
	needs := number.BitLen()
	if needs > bits {
		return 0, fmt.Errorf("Number %s (base %d) needs %d bits, max %d", original, radix, needs, bits)
	}
	if negative {
		number.Neg(number)
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	number.Mod(number, modulus)
	return number.Uint64(), nil
}

func utf16LE(value string, terminated bool) []byte {
	runes := []rune(value)
	if terminated {
		runes = append(runes, 0)
	}
	units := utf16.Encode(runes)
	result := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(result[i*2:], unit)
	}
	return result
}
