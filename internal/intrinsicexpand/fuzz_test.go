// SPDX-License-Identifier: GPL-3.0-only

package intrinsicexpand

import (
	"context"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func FuzzApplyReplacement(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x90})
	f.Add([]byte{0xb8, 0x2a, 0, 0, 0, 0xc3})
	f.Fuzz(func(t *testing.T, replacement []byte) {
		if len(replacement) > 64 {
			t.Skip()
		}
		object, text, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, replacement)
		before := append([]byte(nil), text.Data...)
		result, _, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}})
		if err != nil {
			if string(text.Data) != string(before) {
				t.Fatal("failed Apply mutated source")
			}
			return
		}
		if result == nil || len(result.GetSection(".text").Relocations) != 0 || string(text.Data) != string(before) {
			t.Fatal("successful Apply violated ownership or relocation invariants")
		}
	})
}
