// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package blockparty

import (
	"bytes"
	"context"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func FuzzApplyMalformed(f *testing.F) {
	f.Add(uint16(coff.MachineAMD64), []byte{0xc3})
	f.Add(uint16(coff.MachineAMD64), []byte{0x74, 0x02, 0x90, 0xc3, 0x90, 0xc3})
	f.Add(uint16(coff.MachineI386), []byte{0xeb, 0x00, 0xc3})
	f.Fuzz(func(t *testing.T, rawMachine uint16, input []byte) {
		if len(input) == 0 || len(input) > 256 {
			t.Skip()
		}
		machine := coff.MachineAMD64
		if rawMachine&1 != 0 {
			machine = coff.MachineI386
		}
		object, text, _ := testObject(t, machine, append([]byte(nil), input...))
		before := append([]byte(nil), text.Data...)
		_, err := Apply(context.Background(), object, Options{Disassembler: byteDecoder{}, Seed: seed(19)})
		if err != nil && !bytes.Equal(text.Data, before) {
			t.Fatalf("failed transactional Apply mutated text: %v", err)
		}
	})
}

type byteDecoder struct{}

func (byteDecoder) Disassemble(ctx context.Context, code []byte, address uint64) ([]x86.Instruction, error) {
	result := make([]x86.Instruction, 0, len(code))
	for offset, value := range code {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		mnemonic := "nop"
		if value == 0xc3 {
			mnemonic = "ret"
		}
		result = append(result, x86.Instruction{Address: address + uint64(offset), Bytes: []byte{value}, Mnemonic: mnemonic})
	}
	return result, nil
}

func (byteDecoder) Close(context.Context) error { return nil }
