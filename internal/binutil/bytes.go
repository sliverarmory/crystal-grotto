// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package binutil

import (
	"crypto/rc4" //nolint:gosec // Required for Crystal Palace wire compatibility.
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

var (
	// ErrBounds indicates that a binary operation would access bytes outside
	// the supplied buffer.
	ErrBounds = errors.New("binary access out of bounds")
	// ErrEmptyKey indicates that a repeating-key or RC4 operation received no
	// key bytes.
	ErrEmptyKey = errors.New("key must not be empty")
)

// HexToBytes decodes Crystal Palace's command-line hex format. It deliberately
// removes ASCII spaces only; other whitespace remains invalid. Each two-byte
// group is parsed like Java's Integer.parseInt(group, 16), including an
// optional sign within a group.
func HexToBytes(text string) ([]byte, error) {
	text = strings.ReplaceAll(text, " ", "")
	if len(text)%2 != 0 {
		return nil, errors.New("String length not divisible by 2")
	}

	result := make([]byte, len(text)/2)
	for i := range result {
		group := text[i*2 : i*2+2]
		value, err := strconv.ParseInt(group, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid hex byte %q at offset %d: %w", group, i*2, err)
		}
		result[i] = byte(value)
	}
	return result, nil
}

// BytesToHex formats bytes as lower-case, space-separated hexadecimal, as the
// upstream bytesToHex helper does.
func BytesToHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	const digits = "0123456789abcdef"
	result := make([]byte, len(data)*3-1)
	for i, value := range data {
		if i != 0 {
			result[i*3-1] = ' '
		}
		result[i*3] = digits[value>>4]
		result[i*3+1] = digits[value&0x0f]
	}
	return string(result)
}

// GetDWORD reads a little-endian DWORD from data.
func GetDWORD(data []byte, offset int) (uint32, error) {
	if offset < 0 || len(data) < 4 || offset > len(data)-4 {
		return 0, fmt.Errorf("%w: DWORD at offset %d in %d-byte buffer", ErrBounds, offset, len(data))
	}
	return binary.LittleEndian.Uint32(data[offset : offset+4]), nil
}

// PutDWORD writes a little-endian DWORD into data.
func PutDWORD(data []byte, offset int, value uint32) error {
	if offset < 0 || len(data) < 4 || offset > len(data)-4 {
		return fmt.Errorf("%w: DWORD at offset %d in %d-byte buffer", ErrBounds, offset, len(data))
	}
	binary.LittleEndian.PutUint32(data[offset:offset+4], value)
	return nil
}

// UTF8 returns the UTF-8 bytes of text.
func UTF8(text string) []byte {
	return []byte(text)
}

// UTF8Z returns UTF-8 text followed by a NUL byte.
func UTF8Z(text string) []byte {
	result := make([]byte, len(text)+1)
	copy(result, text)
	return result
}

// UTF16LE returns text encoded as UTF-16LE without a terminator.
func UTF16LE(text string) []byte {
	words := utf16.Encode([]rune(text))
	result := make([]byte, len(words)*2)
	for i, word := range words {
		binary.LittleEndian.PutUint16(result[i*2:], word)
	}
	return result
}

// UTF16LEZ returns text encoded as UTF-16LE followed by a UTF-16 NUL.
func UTF16LEZ(text string) []byte {
	result := UTF16LE(text)
	return append(result, 0, 0)
}

// Reverse returns a reversed copy of data.
func Reverse(data []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[len(data)-1-i]
	}
	return result
}

// Adler32 returns the unsigned Adler-32 checksum used by prepsum and the
// upstream packer.
func Adler32(data []byte) uint32 {
	return adler32.Checksum(data)
}

// RC4Encrypt applies RC4/ARCFOUR and returns a new byte slice. RC4 is retained
// solely for compatibility with existing Crystal Palace specifications.
func RC4Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	cipher, err := rc4.NewCipher(key) //nolint:gosec // Compatibility algorithm.
	if err != nil {
		return nil, fmt.Errorf("create RC4 cipher: %w", err)
	}
	result := make([]byte, len(plaintext))
	cipher.XORKeyStream(result, plaintext)
	return result, nil
}

// XORRepeating applies a repeating XOR key and returns a new byte slice.
func XORRepeating(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrEmptyKey
	}
	result := make([]byte, len(data))
	for i, value := range data {
		result[i] = value ^ key[i%len(key)]
	}
	return result, nil
}

// PrependLength returns data prefixed with its four-byte little-endian length.
func PrependLength(data []byte) ([]byte, error) {
	if uint64(len(data)) > math.MaxUint32 {
		return nil, fmt.Errorf("data length %d does not fit in a DWORD", len(data))
	}
	result := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(result, uint32(len(data)))
	copy(result[4:], data)
	return result, nil
}

// PrependChecksum returns data prefixed with its four-byte little-endian
// Adler-32 checksum.
func PrependChecksum(data []byte) []byte {
	result := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(result, Adler32(data))
	copy(result[4:], data)
	return result
}
