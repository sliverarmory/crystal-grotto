// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// PICO loader instruction opcodes. These values are part of Crystal Palace's
// on-wire PICO format and must not be renumbered.
const (
	PICOInstructionComplete uint8 = iota
	PICOInstructionPatch
	PICOInstructionCopy
	PICOInstructionLoadLibrary
	PICOInstructionGetProcAddress
	PICOInstructionPatchDiff
	PICOInstructionPatchFunction
	PICOInstructionExport
)

const (
	PICOPatchTextText uint8 = iota
	PICOPatchTextData
	PICOPatchDataText
	PICOPatchDataData
)

const (
	PICOContextCode uint8 = 5
	PICOContextData uint8 = 6
)

// Directive is one PICO loader instruction. Its binary header is type,
// option, and a little-endian uint16 total length (including the header).
type Directive struct {
	Type   uint8
	Option uint8
	Data   []byte
}

// MarshalBinary encodes one directive with strict 16-bit length checking.
func (d Directive) MarshalBinary() ([]byte, error) {
	if len(d.Data) > math.MaxUint16-4 {
		return nil, fmt.Errorf("PICO directive payload is %d bytes; maximum is %d", len(d.Data), math.MaxUint16-4)
	}
	result := make([]byte, 4+len(d.Data))
	result[0] = d.Type
	result[1] = d.Option
	binary.LittleEndian.PutUint16(result[2:4], uint16(len(result)))
	copy(result[4:], d.Data)
	return result, nil
}

// EncodeDirectives encodes a loader program in the supplied order.
func EncodeDirectives(directives []Directive) ([]byte, error) {
	var result []byte
	for index, directive := range directives {
		encoded, err := directive.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("directive %d: %w", index, err)
		}
		if len(encoded) > math.MaxInt-len(result) {
			return nil, errors.New("PICO loader program allocation overflow")
		}
		result = append(result, encoded...)
	}
	return result, nil
}

// DecodeDirectives safely decodes a complete PICO loader program. It is
// intentionally generic: opcode-specific payload validation belongs to the
// consumer of the program.
func DecodeDirectives(program []byte) ([]Directive, error) {
	var result []Directive
	for offset := 0; offset < len(program); {
		if len(program)-offset < 4 {
			return nil, fmt.Errorf("PICO directive header at %#x is truncated", offset)
		}
		length := int(binary.LittleEndian.Uint16(program[offset+2 : offset+4]))
		if length < 4 {
			return nil, fmt.Errorf("PICO directive at %#x has invalid length %d", offset, length)
		}
		if length > len(program)-offset {
			return nil, fmt.Errorf("PICO directive at %#x extends beyond %d-byte program", offset, len(program))
		}
		result = append(result, Directive{
			Type:   program[offset],
			Option: program[offset+1],
			Data:   append([]byte(nil), program[offset+4:offset+length]...),
		})
		offset += length
	}
	return result, nil
}

func directiveUint32(instruction, option uint8, values ...uint32) Directive {
	data := make([]byte, len(values)*4)
	for index, value := range values {
		binary.LittleEndian.PutUint32(data[index*4:index*4+4], value)
	}
	return Directive{Type: instruction, Option: option, Data: data}
}

func directiveString(instruction uint8, value string) (Directive, error) {
	for _, character := range value {
		if character == 0 {
			return Directive{}, errors.New("PICO directive string contains NUL")
		}
	}
	data := append([]byte(value), 0)
	directive := Directive{Type: instruction, Data: data}
	if _, err := directive.MarshalBinary(); err != nil {
		return Directive{}, err
	}
	return directive, nil
}
