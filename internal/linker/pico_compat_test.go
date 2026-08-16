// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"bytes"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestEmitPICODuplicateImportsAndAPIsUseFirstIndex(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 8)
	imported := testUndefined(t, object, "__imp_Custom", coff.SymbolTypeFunction)
	testRelocation(text, 0, coff.RelAMD64Rel32, imported)
	testRelocation(text, 4, coff.RelAMD64Rel32, imported)

	options := PICOOptions{APIs: []string{
		"LoadLibraryA",
		"GetProcAddress",
		"Custom",
		"LoadLibraryA",
		"GetProcAddress",
		"Custom",
	}}
	image, err := EmitPICO(object, options)
	if err != nil {
		t.Fatal(err)
	}

	// ProgramPICO creates one IAT slot per relocation symbol, not one slot per
	// reference. Both references still need their own code-to-data base patch.
	if got, want := image.Header.DataLength, uint32(8); got != want {
		t.Fatalf("data length = %d, want one %d-byte import slot", got, want)
	}
	var patchDiffs, patchFunctions []Directive
	for _, directive := range image.Directives {
		switch directive.Type {
		case PICOInstructionPatchDiff:
			patchDiffs = append(patchDiffs, directive)
		case PICOInstructionPatchFunction:
			patchFunctions = append(patchFunctions, directive)
		}
	}
	if got, want := len(patchDiffs), 2; got != want {
		t.Fatalf("PATCH_DIFF directives = %d, want %d", got, want)
	}
	if got, want := len(patchFunctions), 1; got != want {
		t.Fatalf("PATCH_FUNC directives = %d, want %d", got, want)
	}
	if got, want := patchFunctions[0].Option, uint8(3); got != want {
		t.Fatalf("duplicate API option = %d, want first-index option %d", got, want)
	}
	if got := directiveValue(t, patchFunctions[0], 0); got != 0 {
		t.Fatalf("import slot offset = %d, want 0", got)
	}

	again, err := EmitPICO(object, options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(image.Bytes, again.Bytes) {
		t.Fatal("duplicate import/API output is not deterministic")
	}
}

func TestEmitPICODuplicateAPITableCanExceedWireIndexSpace(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 4)
	imported := testUndefined(t, object, "__imp_Custom", coff.SymbolTypeFunction)
	testRelocation(text, 0, coff.RelAMD64Rel32, imported)

	// Only the first matching index is encoded. Duplicate tail entries have no
	// wire representation and upstream accepts them, so their count alone must
	// not make an otherwise encodable table fail.
	apis := []string{"LoadLibraryA", "GetProcAddress", "Custom"}
	for len(apis) < 300 {
		apis = append(apis, "Custom")
	}
	image, err := EmitPICO(object, PICOOptions{APIs: apis})
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range image.Directives {
		if directive.Type == PICOInstructionPatchFunction {
			if got, want := directive.Option, uint8(3); got != want {
				t.Fatalf("PATCH_FUNC option = %d, want first-index option %d", got, want)
			}
			return
		}
	}
	t.Fatal("missing PATCH_FUNC directive")
}

func TestEmitPICORejectsReferencedAPIOutsideWireIndexSpace(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 4)
	imported := testUndefined(t, object, "__imp_TooLate", coff.SymbolTypeFunction)
	testRelocation(text, 0, coff.RelAMD64Rel32, imported)

	apis := []string{"LoadLibraryA", "GetProcAddress"}
	for len(apis) < 255 {
		apis = append(apis, "unused")
	}
	apis = append(apis, "TooLate")
	if _, err := EmitPICO(object, PICOOptions{APIs: apis}); err == nil {
		t.Fatal("unencodable referenced API index unexpectedly accepted")
	}
}

func TestEmitPICOExportReplacementKeepsDeterministicOrder(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 12)
	testFunction(t, object, text, "one", 0)
	testFunction(t, object, text, "two", 4)
	testFunction(t, object, text, "three", 8)

	options := PICOOptions{Exports: []Export{
		{Symbol: "one", Tag: 0x11},
		{Symbol: "two", Tag: 0x22},
		{Symbol: "one", Tag: 0x33},
		// Replacing one's tag releases 0x11 for a later export.
		{Symbol: "three", Tag: 0x11},
	}}
	image, err := EmitPICO(object, options)
	if err != nil {
		t.Fatal(err)
	}

	var exports []Directive
	for _, directive := range image.Directives {
		if directive.Type == PICOInstructionExport {
			exports = append(exports, directive)
		}
	}
	if got, want := len(exports), 3; got != want {
		t.Fatalf("EXPORT directives = %d, want %d", got, want)
	}
	want := [][2]uint32{{0x33, 0}, {0x22, 4}, {0x11, 8}}
	for index, expected := range want {
		if tag, offset := directiveValue(t, exports[index], 0), directiveValue(t, exports[index], 1); tag != expected[0] || offset != expected[1] {
			t.Fatalf("EXPORT %d = tag %#x offset %d, want tag %#x offset %d", index, tag, offset, expected[0], expected[1])
		}
	}

	again, err := EmitPICO(object, options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(image.Bytes, again.Bytes) {
		t.Fatal("replacement export output is not deterministic")
	}
}
