// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package unwindgen

import (
	"context"
	"errors"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/hooks"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func FuzzGenerateMalformed(f *testing.F) {
	f.Add([]byte{0xc3})
	f.Add([]byte{0x55, 0xc3})
	f.Add([]byte{0x48, 0x83, 0xec, 0x20, 0xc3})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 512 {
			t.Skip()
		}
		code := append([]byte(nil), input...)
		if len(code) == 0 {
			code = []byte{0xc3}
		}
		object, _ := unwindObject(t, code, map[string]uint32{"fuzz": 0})
		decoder := &testDecoder{decode: fuzzInstructions}
		result, err := Generate(context.Background(), object, hooks.Snapshot{}, Options{Disassembler: decoder})
		if err != nil {
			var typed *Error
			var unsupported *UnsupportedError
			var dynamic *DynamicFrameError
			if !errors.As(err, &typed) && !errors.As(err, &unsupported) && !errors.As(err, &dynamic) {
				t.Fatalf("untyped error: %T %v", err, err)
			}
			return
		}
		if _, err := BuildResource("fuzz", result); err != nil {
			t.Fatalf("BuildResource after successful Generate: %v", err)
		}
	})
}

func fuzzInstructions(ctx context.Context, code []byte, address uint64) ([]x86.Instruction, error) {
	result := make([]x86.Instruction, 0, len(code))
	for offset, value := range code {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mnemonic, operands := "nop", ""
		switch value {
		case 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57:
			mnemonic, operands = "push", "rax"
		case 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f:
			mnemonic, operands = "pop", "rax"
		case 0xc3:
			mnemonic = "ret"
		case 0xe8:
			mnemonic = "call"
		}
		result = append(result, x86.Instruction{Address: address + uint64(offset), Bytes: []byte{value}, Mnemonic: mnemonic, Operands: operands})
	}
	return result, nil
}
