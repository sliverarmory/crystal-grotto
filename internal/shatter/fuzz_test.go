// SPDX-License-Identifier: GPL-3.0-only

package shatter

import (
	"bytes"
	"context"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func FuzzApplyInstructionStream(f *testing.F) {
	f.Add([]byte{0xeb, 0x00, 0xc3}, true, int64(123))
	f.Add([]byte{0x75, 0x02, 0x90, 0xc3, 0x90}, false, int64(-1))
	f.Add([]byte{0xc7, 0xf8, 0, 0, 0, 0, 0xc3}, true, int64(0))
	f.Fuzz(func(t *testing.T, code []byte, mode64 bool, seed int64) {
		if len(code) > 256 {
			t.Skip()
		}
		machine := coff.MachineI386
		if mode64 {
			machine = coff.MachineAMD64
		}
		object, err := coff.NewObject(machine)
		if err != nil {
			t.Fatal(err)
		}
		text := coff.NewSection(".text", code)
		if err := object.AddSection(text); err != nil {
			t.Fatal(err)
		}
		if len(code) != 0 {
			if err := object.AddSymbol(coff.NewFunctionSymbol(text, "go", 0)); err != nil {
				t.Fatal(err)
			}
		}
		before := append([]byte(nil), text.Data...)
		_, applyErr := Apply(context.Background(), object, Options{Seed: &seed})
		if applyErr != nil && !bytes.Equal(text.Data, before) {
			t.Fatalf("failed Apply changed .text: %x -> %x (%v)", before, text.Data, applyErr)
		}
	})
}

func FuzzRelativeDecoderAndJavaHash(f *testing.F) {
	f.Add([]byte{0xe9, 1, 0, 0, 0}, "helper")
	f.Add([]byte{0x0f, 0x85, 0xfe, 0xff, 0xff, 0xff}, "go")
	f.Add([]byte{0xe2, 0x7f}, "\U0001f48e")
	f.Fuzz(func(t *testing.T, raw []byte, name string) {
		if len(raw) > 32 || len(name) > 128 {
			t.Skip()
		}
		reference, ok := decodeRelative(raw)
		if ok {
			entry := &instruction{oldStart: 0x1000, oldEnd: 0x1000 + uint32(len(raw)), raw: append([]byte(nil), raw...)}
			_, _ = relativeTarget(entry, reference)
		}
		_, _ = javaHashOrder([]*region{{name: name}, {name: name + "x"}})
	})
}
