// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestDirectiveCodec(t *testing.T) {
	directives := []Directive{
		directiveUint32(PICOInstructionCopy, PICOContextCode, 1, 2, 3),
		{Type: PICOInstructionComplete},
	}
	encoded, err := EncodeDirectives(directives)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{PICOInstructionCopy, PICOContextCode, 16, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, PICOInstructionComplete, 0, 4, 0}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded = %x, want %x", encoded, want)
	}
	decoded, err := DecodeDirectives(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Type != directives[0].Type || !bytes.Equal(decoded[0].Data, directives[0].Data) || decoded[1].Type != PICOInstructionComplete {
		t.Fatalf("decoded = %#v", decoded)
	}
	decoded[0].Data[0] ^= 0xff
	if bytes.Equal(decoded[0].Data, encoded[4:16]) {
		t.Fatal("decoded payload aliases encoded input")
	}
}

func TestDirectiveCodecRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "truncated header", data: []byte{1, 2, 3}},
		{name: "short length", data: []byte{1, 2, 3, 0}},
		{name: "past end", data: []byte{1, 2, 8, 0, 0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeDirectives(test.data); err == nil {
				t.Fatal("DecodeDirectives succeeded")
			}
		})
	}
	tooLarge := Directive{Data: make([]byte, 65532)}
	if _, err := tooLarge.MarshalBinary(); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("large directive error = %v", err)
	}
}

func TestPICOHeaderCodec(t *testing.T) {
	header := PICOHeader{CodeLength: 1, DataLength: 2, ResourceOffset: 3, EntryAddress: 4}
	encoded := header.MarshalBinary()
	if len(encoded) != PICOHeaderSize || binary.LittleEndian.Uint32(encoded[12:]) != 4 {
		t.Fatalf("encoded header = %x", encoded)
	}
	decoded, err := ParsePICOHeader(encoded)
	if err != nil || decoded != header {
		t.Fatalf("decoded = %#v, %v", decoded, err)
	}
	if _, err := ParsePICOHeader(encoded[:15]); err == nil {
		t.Fatal("truncated header succeeded")
	}
}

func TestLayoutAlignmentAndSparseTail(t *testing.T) {
	first := coffSectionForLayout("first", 3, 1)
	second := coffSectionForLayout("second", 2, 4)
	bss := coffSectionForLayout(".bss", 5, 8)
	layout, err := makeLayout([]layoutEntry{{section: first}, {section: second}, {section: bss, sparse: true}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(layout.Bytes), 8; got != want {
		t.Fatalf("real length = %d, want %d", got, want)
	}
	if got, want := layout.VirtualSize, uint32(13); got != want {
		t.Fatalf("virtual length = %d, want %d", got, want)
	}
	if placement, _ := layout.Placement(second); placement.Offset != 4 {
		t.Fatalf("second offset = %d, want 4", placement.Offset)
	}
	if placement, _ := layout.Placement(bss); placement.Offset != 8 || !placement.Sparse {
		t.Fatalf("BSS placement = %#v", placement)
	}
	if _, err := makeLayout([]layoutEntry{{section: bss, sparse: true}, {section: first}}); err == nil || !strings.Contains(err.Error(), "follows sparse") {
		t.Fatalf("section-after-sparse error = %v", err)
	}
}

func coffSectionForLayout(name string, size int, alignment uint32) *coff.Section {
	section := coff.NewSection(name, make([]byte, size))
	section.Alignment = alignment
	return section
}

func FuzzDecodeDirectives(f *testing.F) {
	f.Add([]byte{PICOInstructionComplete, 0, 4, 0})
	f.Add([]byte{PICOInstructionCopy, PICOContextCode, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		directives, err := DecodeDirectives(data)
		if err != nil {
			return
		}
		reencoded, err := EncodeDirectives(directives)
		if err != nil {
			t.Fatalf("valid decoded directives failed to encode: %v", err)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatalf("round trip mismatch: %x != %x", reencoded, data)
		}
	})
}
