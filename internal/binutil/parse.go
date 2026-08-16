// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package binutil

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode"
)

// DecodeNumber parses Crystal Palace's decimal, octal, and hexadecimal number
// syntax and enforces its magnitude bit limit. A leading zero selects octal;
// lower-case 0x or # selects hexadecimal.
func DecodeNumber(original string, maxBits int) (*big.Int, error) {
	negative := false
	value := original
	if strings.HasPrefix(value, "-") {
		negative = true
		value = value[1:]
	} else if strings.HasPrefix(value, "+") {
		value = value[1:]
	}

	radix := 10
	if strings.HasPrefix(value, "0x") {
		radix = 16
		value = value[2:]
	} else if strings.HasPrefix(value, "0") && len(value) > 1 {
		radix = 8
		value = value[1:]
	} else if strings.HasPrefix(value, "#") {
		radix = 16
		value = value[1:]
	}

	number, ok := new(big.Int).SetString(value, radix)
	if !ok {
		return nil, fmt.Errorf("Can't decode %s as base %d number", original, radix)
	}

	needed := javaBitLength(number)
	if needed > maxBits {
		return nil, fmt.Errorf("Number %s (base %d) needs %d bits, max %d", original, radix, needed, maxBits)
	}
	if negative {
		number.Neg(number)
	}
	return number, nil
}

// javaBitLength implements BigInteger.bitLength, including its two's-
// complement behavior for negative values.
func javaBitLength(number *big.Int) int {
	if number.Sign() >= 0 {
		return number.BitLen()
	}
	magnitudeMinusOne := new(big.Int).Abs(number)
	magnitudeMinusOne.Sub(magnitudeMinusOne, big.NewInt(1))
	return magnitudeMinusOne.BitLen()
}

// LowBits returns the low bits of number using Java's narrowing-conversion
// semantics. It is useful after DecodeNumber when packing byte, short, int, or
// long values.
func LowBits(number *big.Int, bits uint) (uint64, error) {
	if number == nil {
		return 0, errors.New("number is nil")
	}
	if bits == 0 || bits > 64 {
		return 0, fmt.Errorf("bit width must be in 1..64, got %d", bits)
	}
	modulus := new(big.Int).Lsh(big.NewInt(1), bits)
	low := new(big.Int).Mod(new(big.Int).Set(number), modulus)
	return low.Uint64(), nil
}

// ParseInt32 parses a base-10 signed integer with Java Integer.parseInt's
// 32-bit bounds.
func ParseInt32(text string) (int32, error) {
	value, err := strconv.ParseInt(text, 10, 32)
	if err != nil {
		return 0, err
	}
	return int32(value), nil
}

// SplitList implements Crystal Palace's comma-list rules: surrounding ASCII
// control/space characters are trimmed and trailing empty fields are dropped.
func SplitList(text string) []string {
	if text == "" {
		return []string{}
	}
	parts := strings.Split(text, ",")
	for i := range parts {
		parts[i] = strings.TrimFunc(parts[i], func(r rune) bool { return r <= ' ' })
	}
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// SplitSet returns SplitList's values with duplicate entries removed while
// preserving first-seen order, matching LinkedHashSet.
func SplitSet(text string) []string {
	values := SplitList(text)
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// ParseKeyValue splits text at its first equals sign. Empty keys and values are
// valid, as they are upstream.
func ParseKeyValue(text string) (key, value string, err error) {
	index := strings.IndexByte(text, '=')
	if index < 0 {
		return "", "", fmt.Errorf("Argument %s is not in KEY=VALUE format", text)
	}
	return text[:index], text[index+1:], nil
}

// Range is the parsed form of an inclusive-looking Crystal Palace ##-## range.
// Consumers decide endpoint semantics; the parser only requires Min < Max.
type Range struct {
	Min int32
	Max int32
}

// ParseRange parses the upstream ##-## syntax and preserves its parseInt
// fallback of -1 for numeric overflow or otherwise unparseable digit strings.
func ParseRange(text string) (Range, error) {
	runes := []rune(text)
	left := make([]rune, 0, len(runes))
	separator := -1
	for i, r := range runes {
		if unicode.IsDigit(r) {
			left = append(left, r)
			continue
		}
		if r == '-' {
			separator = i
			break
		}
		return Range{}, fmt.Errorf("Could not parse ##-##: Unexpected character '%c' in %s", r, text)
	}
	if separator < 0 || separator+1 >= len(runes) {
		return Range{}, fmt.Errorf("Could not parse ##-##: String %s is not in ##-## format", text)
	}

	right := make([]rune, 0, len(runes)-separator-1)
	for _, r := range runes[separator+1:] {
		if !unicode.IsDigit(r) {
			return Range{}, fmt.Errorf("Could not parse ##-##: Unexpected character '%c' in %s", r, text)
		}
		right = append(right, r)
	}

	minimum := parseInt32OrMinusOne(string(left))
	maximum := parseInt32OrMinusOne(string(right))
	result := Range{Min: minimum, Max: maximum}
	if minimum >= maximum {
		return result, fmt.Errorf("Invalid range. %d >= %d from %s", minimum, maximum, text)
	}
	return result, nil
}

func parseInt32OrMinusOne(text string) int32 {
	value, err := ParseInt32(text)
	if err != nil {
		return -1
	}
	return value
}
