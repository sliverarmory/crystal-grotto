// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package safety

import (
	"context"
	"errors"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func FuzzCheckMalformed(f *testing.F) {
	f.Add([]byte{0xc3}, uint8(0), uint16(0))
	f.Add([]byte{0xe8, 0, 0, 0, 0}, uint8(1), coff.RelAMD64Rel32)
	f.Add([]byte{0xff, 0xd0, 0xc3}, uint8(2), uint16(0xffff))
	f.Fuzz(func(t *testing.T, input []byte, relocationByte uint8, relocationType uint16) {
		if len(input) > 256 {
			t.Skip()
		}
		code := append([]byte(nil), input...)
		if len(code) == 0 {
			code = []byte{0xc3}
		}
		object, text := objectWithFunctions(t, coff.MachineAMD64, code, map[string]uint32{"root": 0})
		if relocationByte&1 != 0 {
			text.Relocations = append(text.Relocations, &coff.Relocation{
				Section: text, VirtualAddress: uint32(relocationByte) % uint32(len(code)), SymbolName: "external", Type: relocationType,
			})
		}
		decoder := &testDisassembler{disassemble: oneByteInstructions}
		_, err := CheckRoot(context.Background(), object, "root", Options{Disassembler: decoder})
		if err != nil && !errors.Is(err, ErrUnproven) && !errors.Is(err, ErrDangerousDprintf) {
			t.Fatalf("untyped error: %T %v", err, err)
		}
	})
}

func oneByteInstructions(ctx context.Context, code []byte, address uint64) ([]x86.Instruction, error) {
	instructions := make([]x86.Instruction, 0, len(code))
	for offset, value := range code {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mnemonic := "nop"
		switch value {
		case 0xe8:
			mnemonic = "call"
		case 0xe9, 0xeb, 0xff:
			mnemonic = "jmp"
		}
		instructions = append(instructions, x86.Instruction{
			Address: address + uint64(offset), Bytes: []byte{value}, Mnemonic: mnemonic,
		})
	}
	return instructions, nil
}
