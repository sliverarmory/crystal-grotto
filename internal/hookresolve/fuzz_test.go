// SPDX-License-Identifier: GPL-3.0-only

package hookresolve

import (
	"fmt"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
)

func FuzzEncodeStub(f *testing.F) {
	f.Add(byte(0), byte(0))
	f.Add(byte(1), byte(4))
	f.Fuzz(func(t *testing.T, architecture, countByte byte) {
		machine := coff.MachineI386
		if architecture&1 != 0 {
			machine = coff.MachineAMD64
		}
		count := int(countByte % 17)
		entries := make([]hooks.ResolveHook, count)
		wrappers := make([]string, count)
		for index := range entries {
			entries[index] = hooks.ResolveHook{Function: fmt.Sprintf("Function%d", index)}
			wrappers[index] = fmt.Sprintf("wrapper%d", index)
		}
		code, relocations, err := encodeStub(machine, entries, wrappers)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) == 0 || code[len(code)-1] != 0xc3 || len(relocations) != count {
			t.Fatalf("encoded stub length=%d relocs=%d count=%d", len(code), len(relocations), count)
		}
		for index, relocation := range relocations {
			if relocation.wrapper != wrappers[index] || int(relocation.offset)+4 > len(code) {
				t.Fatalf("relocation[%d] = %#v", index, relocation)
			}
		}
	})
}
