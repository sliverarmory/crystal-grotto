// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package transfer

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func FuzzApplyTransactional(f *testing.F) {
	f.Add([]byte{0xe8, 0, 0, 0, 0, 0x90, 0xc3}, uint8(0))
	f.Add([]byte{0x53, 0x48, 0x83, 0xec, 0x20, 0xe8, 0, 0, 0, 0, 0xc3}, uint8(5))
	f.Add([]byte{0xc7, 0xf8, 0, 0, 0, 0, 0xc3}, uint8(0))
	f.Fuzz(func(t *testing.T, input []byte, rawCall uint8) {
		if len(input) < 5 || len(input) > 256 {
			t.Skip()
		}
		code := append([]byte(nil), input...)
		call := uint32(int(rawCall) % (len(code) - 4))
		object, text, function, relocation := testTransferObject(t, coff.MachineAMD64, code, call)
		beforeText := append([]byte(nil), text.Data...)
		beforeRelocations := append([]*coff.Relocation(nil), text.Relocations...)
		beforeFunction := function.Value
		beforeVA := relocation.VirtualAddress
		_, err := Apply(context.Background(), object, Options{Disassembler: fuzzDecoder{}})
		if err == nil {
			return
		}
		if !bytes.Equal(text.Data, beforeText) || fmt.Sprint(text.Relocations) != fmt.Sprint(beforeRelocations) || function.Value != beforeFunction || relocation.VirtualAddress != beforeVA {
			t.Fatalf("failed Apply mutated object: %v", err)
		}
	})
}

type fuzzDecoder struct{}

func (fuzzDecoder) Disassemble(ctx context.Context, code []byte, address uint64) ([]x86.Instruction, error) {
	result := make([]x86.Instruction, 0, len(code))
	for offset := 0; offset < len(code); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		length := 1
		mnemonic := "nop"
		operands := ""
		value := code[offset]
		switch {
		case value >= 0x50 && value <= 0x57:
			mnemonic = "push"
			operands = registerNames[value-0x50]
		case value == 0x41 && offset+1 < len(code) && code[offset+1] >= 0x50 && code[offset+1] <= 0x57:
			length = 2
			mnemonic = "push"
			operands = registerNames[8+code[offset+1]-0x50]
		case value == 0x48 && offset+3 < len(code) && code[offset+1] == 0x83 && code[offset+2] == 0xec:
			length = 4
			mnemonic = "sub"
			operands = "rsp, 0x1"
		case value == 0x48 && offset+6 < len(code) && code[offset+1] == 0x81 && code[offset+2] == 0xec:
			length = 7
			mnemonic = "sub"
			operands = "rsp, 0x100"
		case value == 0xe8 && offset+4 < len(code):
			length = 5
			mnemonic = "call"
			operands = "0x0"
		case value == 0x90:
			mnemonic = "nop"
		case value == 0xc3:
			mnemonic = "ret"
		}
		raw := append([]byte(nil), code[offset:offset+length]...)
		result = append(result, x86.Instruction{Address: address + uint64(offset), Bytes: raw, Mnemonic: mnemonic, Operands: operands})
		offset += length
	}
	return result, nil
}

func (fuzzDecoder) Close(context.Context) error { return nil }
