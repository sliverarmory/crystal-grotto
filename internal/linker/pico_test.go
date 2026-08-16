// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func complexPICOObject(t testing.TB) *coff.Object {
	t.Helper()
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 16)
	data := testSection(t, object, ".data", 8)
	bss := testSection(t, object, ".bss", 16)
	unwind := testSection(t, object, ".cpl_unwind", 4)
	unwind.Alignment = 4
	_ = bss

	testFunction(t, object, text, "go", 0)
	helper := testFunction(t, object, text, "helper", 12)
	global := testDataSymbol(t, object, data, "global", 0)
	external := testUndefined(t, object, "__imp_KERNEL32$Sleep", coff.SymbolTypeFunction)
	internal := testUndefined(t, object, "__imp_MyAPI", coff.SymbolTypeFunction)
	testRelocation(text, 0, coff.RelAMD64Rel32, external)
	testRelocation(text, 4, coff.RelAMD64Rel32, global)
	testRelocation(text, 8, coff.RelAMD64Rel32, internal)
	testRelocation(data, 0, coff.RelAMD64Addr64, helper)
	return object
}

func TestEmitPICOAMD64WireFormat(t *testing.T) {
	object := complexPICOObject(t)
	options := PICOOptions{
		RequireEntry: true,
		APIs:         []string{"LoadLibraryA", "GetProcAddress", "MyAPI"},
		Exports:      []Export{{Symbol: "helper", Tag: 0x12345678}},
	}
	image, err := EmitPICO(object, options)
	if err != nil {
		t.Fatal(err)
	}
	if image.Header.CodeLength != 20 || len(image.Code) != 20 {
		t.Fatalf("code lengths = virtual %d, real %d; want 20, 20", image.Header.CodeLength, len(image.Code))
	}
	if image.Header.DataLength != 40 || len(image.Data) != 24 {
		t.Fatalf("data lengths = virtual %d, real %d; want 40, 24", image.Header.DataLength, len(image.Data))
	}
	if !image.HasEntry || image.EntryOffset != 0 || image.Header.EntryAddress != 0 {
		t.Fatalf("entry = (%v, %#x), header %#x", image.HasEntry, image.EntryOffset, image.Header.EntryAddress)
	}
	if got, want := image.Header.ResourceOffset, uint32(PICOHeaderSize+len(image.Program)); got != want {
		t.Fatalf("resource offset = %d, want %d", got, want)
	}
	if got, want := len(image.Bytes), int(image.Header.ResourceOffset)+len(image.Code)+len(image.Data); got != want {
		t.Fatalf("wire length = %d, want %d", got, want)
	}
	parsedHeader, err := ParsePICOHeader(image.Bytes)
	if err != nil || parsedHeader != image.Header {
		t.Fatalf("parsed header = %#v, %v; want %#v", parsedHeader, err, image.Header)
	}
	decoded, err := DecodeDirectives(image.Program)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 13 {
		for index, directive := range decoded {
			t.Logf("directive %d: type=%d option=%d data=%x", index, directive.Type, directive.Option, directive.Data)
		}
		t.Fatalf("directive count = %d, want 13", len(decoded))
	}

	if decoded[0].Type != PICOInstructionCopy || decoded[0].Option != PICOContextCode || directiveValue(t, decoded[0], 0) != 0 || directiveValue(t, decoded[0], 1) != 0 || directiveValue(t, decoded[0], 2) != 20 {
		t.Fatalf("code COPY = %#v", decoded[0])
	}
	if decoded[1].Type != PICOInstructionCopy || decoded[1].Option != PICOContextData || directiveValue(t, decoded[1], 0) != 20 || directiveValue(t, decoded[1], 1) != 0 || directiveValue(t, decoded[1], 2) != 24 {
		t.Fatalf("data COPY = %#v", decoded[1])
	}
	for index, patchOffset := range []uint32{0, 4, 8} {
		directive := decoded[index+2]
		if directive.Type != PICOInstructionPatchDiff || directive.Option != 0 || directiveValue(t, directive, 0) != patchOffset {
			t.Fatalf("PATCH_DIFF %d = %#v", index, directive)
		}
	}
	if directive := decoded[5]; directive.Type != PICOInstructionPatch || directive.Option != PICOPatchDataText || directiveValue(t, directive, 0) != 16 {
		t.Fatalf("data->text PATCH = %#v", directive)
	}
	if decoded[6].Type != PICOInstructionLoadLibrary || directiveText(t, decoded[6]) != "KERNEL32" {
		t.Fatalf("LL = %#v", decoded[6])
	}
	if decoded[7].Type != PICOInstructionGetProcAddress || directiveText(t, decoded[7]) != "Sleep" {
		t.Fatalf("GPA = %#v", decoded[7])
	}
	if decoded[8].Type != PICOInstructionPatchFunction || decoded[8].Option != 0 || directiveValue(t, decoded[8], 0) != 0 {
		t.Fatalf("external PATCH_FUNC = %#v", decoded[8])
	}
	if decoded[9].Type != PICOInstructionPatchFunction || decoded[9].Option != 3 || directiveValue(t, decoded[9], 0) != 8 {
		t.Fatalf("internal PATCH_FUNC = %#v", decoded[9])
	}
	if decoded[10].Type != PICOInstructionExport || directiveValue(t, decoded[10], 0) != 0x12345678 || directiveValue(t, decoded[10], 1) != 12 {
		t.Fatalf("user EXPORT = %#v", decoded[10])
	}
	if decoded[11].Type != PICOInstructionExport || directiveValue(t, decoded[11], 0) != PICOUnwindExportTag || directiveValue(t, decoded[11], 1) != 16 {
		t.Fatalf("unwind EXPORT = %#v", decoded[11])
	}
	if decoded[12].Type != PICOInstructionComplete {
		// Keep this assertion separate from the exact count below so an import
		// grouping regression prints the unexpected tail clearly.
		t.Fatalf("expected COMPLETE at 12, got %#v", decoded[12])
	}
	if got := int32(binary.LittleEndian.Uint32(image.Code[0:4])); got != -4 {
		t.Fatalf("external import displacement = %d, want -4", got)
	}
	if got := int32(binary.LittleEndian.Uint32(image.Code[4:8])); got != 8 {
		t.Fatalf("data displacement = %d, want 8", got)
	}
	if got := int32(binary.LittleEndian.Uint32(image.Code[8:12])); got != -4 {
		t.Fatalf("internal import displacement = %d, want -4", got)
	}
	if got := binary.LittleEndian.Uint32(image.Data[16:20]); got != 12 {
		t.Fatalf("data ADDR64 low DWORD = %d, want 12", got)
	}

	again, err := EmitPICO(object, options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(image.Bytes, again.Bytes) {
		t.Fatal("PICO output is not deterministic")
	}
}

func TestEmitPICOBSSMaterialization(t *testing.T) {
	object := complexPICOObject(t)
	options := PICOOptions{APIs: []string{"LoadLibraryA", "GetProcAddress", "MyAPI"}}
	sparse, err := EmitPICO(object, options)
	if err != nil {
		t.Fatal(err)
	}
	options.MaterializeBSS = true
	materialized, err := EmitPICO(object, options)
	if err != nil {
		t.Fatal(err)
	}
	if sparse.Header.DataLength != materialized.Header.DataLength {
		t.Fatalf("virtual data lengths differ: %d and %d", sparse.Header.DataLength, materialized.Header.DataLength)
	}
	if got := len(materialized.Data) - len(sparse.Data); got != 16 {
		t.Fatalf("materialized BSS delta = %d, want 16", got)
	}
	if !bytes.Equal(materialized.Data[len(sparse.Data):], make([]byte, 16)) {
		t.Fatal("materialized BSS is not zero-filled")
	}
	if directiveValue(t, materialized.Directives[1], 2) != uint32(len(materialized.Data)) {
		t.Fatal("materialized COPY length was not updated")
	}
}

func TestEmitPICOMissingEntryUsesMinusOne(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	testSection(t, object, ".text", 1)
	image, err := EmitPICO(object, PICOOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if image.HasEntry || image.EntryOffset != math.MaxUint32 || image.Header.EntryAddress != math.MaxUint32 {
		t.Fatalf("missing entry = (%v, %#x, %#x)", image.HasEntry, image.EntryOffset, image.Header.EntryAddress)
	}
	if _, err := EmitPICO(object, PICOOptions{RequireEntry: true}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("required entry error = %v", err)
	}
}

func TestEmitPICOImportOrderingAndDecoration(t *testing.T) {
	object := testObject(t, coff.MachineI386)
	text := testSection(t, object, ".text", 12)
	testFunction(t, object, text, "_go", 0)
	first := testUndefined(t, object, "__imp__USER32$MessageBoxA@16", coff.SymbolTypeFunction)
	second := testUndefined(t, object, "__imp_KERNEL32$Sleep@4", coff.SymbolTypeFunction)
	third := testUndefined(t, object, "__imp__USER32$DispatchMessageA@4", coff.SymbolTypeFunction)
	testRelocation(text, 0, coff.RelI386Dir32, first)
	testRelocation(text, 4, coff.RelI386Dir32, second)
	testRelocation(text, 8, coff.RelI386Dir32, third)

	image, err := EmitPICO(object, PICOOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var importProgram []string
	for _, directive := range image.Directives {
		switch directive.Type {
		case PICOInstructionLoadLibrary:
			importProgram = append(importProgram, "LL:"+directiveText(t, directive))
		case PICOInstructionGetProcAddress:
			importProgram = append(importProgram, "GPA:"+directiveText(t, directive))
		}
	}
	if got, want := strings.Join(importProgram, ","), "LL:USER32,GPA:MessageBoxA,GPA:DispatchMessageA,LL:KERNEL32,GPA:Sleep"; got != want {
		t.Fatalf("import order = %q, want %q", got, want)
	}
}

func TestEmitPICOX86LocalRelocations(t *testing.T) {
	object := testObject(t, coff.MachineI386)
	text := testSection(t, object, ".text", 8)
	data := testSection(t, object, ".data", 4)
	targetCode := testFunction(t, object, text, "target", 4)
	targetData := testDataSymbol(t, object, data, "global", 0)
	testRelocation(text, 0, coff.RelI386Rel32, targetCode)
	testRelocation(text, 4, coff.RelI386Dir32, targetData)
	testRelocation(data, 0, coff.RelI386Dir32, targetCode)

	image, err := EmitPICO(object, PICOOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(image.Code[4:8]); got != 0 {
		t.Fatalf("code DIR32 target offset = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(image.Data[:4]); got != 4 {
		t.Fatalf("data DIR32 target offset = %d, want 4", got)
	}
	var patches []Directive
	for _, directive := range image.Directives {
		if directive.Type == PICOInstructionPatch {
			patches = append(patches, directive)
		}
	}
	if len(patches) != 2 || patches[0].Option != PICOPatchTextData || directiveValue(t, patches[0], 0) != 4 || patches[1].Option != PICOPatchDataText || directiveValue(t, patches[1], 0) != 0 {
		t.Fatalf("x86 patches = %#v", patches)
	}
}

func TestEmitPICOAMD64ADDR32NBAndLinks(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 8)
	linked := testUndefined(t, object, "helper_blob", 0)
	testRelocation(text, 0, coff.RelAMD64Addr32NB, linked)
	textSymbol := object.GetSymbol(".text")
	putTestAddend(t, text, 4, 3)
	testRelocation(text, 4, coff.RelAMD64Addr32NB, textSymbol)

	image, err := EmitPICO(object, PICOOptions{Links: []LinkedSection{{Name: "helper_blob", Data: []byte{0xaa, 0xbb}, Executable: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(image.Code[:4]); got != 8 {
		t.Fatalf("linked ADDR32NB = %d, want 8", got)
	}
	if got := binary.LittleEndian.Uint32(image.Code[4:8]); got != 3 {
		t.Fatalf("swallowed .text ADDR32NB = %d, want 3", got)
	}
	if placement, ok := image.CodeLayout.SectionPlacement("helper_blob"); !ok || placement.Offset != 8 {
		t.Fatalf("linked placement = %#v, %v", placement, ok)
	}
}

func TestEmitPICORejectsUnsupportedInputs(t *testing.T) {
	t.Run("import relocation type", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		imported := testUndefined(t, object, "__imp_KERNEL32$Sleep", coff.SymbolTypeFunction)
		testRelocation(text, 0, coff.RelAMD64Rel32_1, imported)
		if _, err := EmitPICO(object, PICOOptions{}); err == nil || !strings.Contains(err.Error(), "invalid type") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("missing internal API", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		imported := testUndefined(t, object, "__imp_Custom", coff.SymbolTypeFunction)
		testRelocation(text, 0, coff.RelAMD64Rel32, imported)
		if _, err := EmitPICO(object, PICOOptions{}); err == nil || !strings.Contains(err.Error(), "not imported") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("bad API prefix", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		testSection(t, object, ".text", 1)
		if _, err := EmitPICO(object, PICOOptions{APIs: []string{"GetProcAddress", "LoadLibraryA"}}); err == nil || !strings.Contains(err.Error(), "first two") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("data REL32", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		data := testSection(t, object, ".data", 4)
		target := testFunction(t, object, text, "target", 0)
		testRelocation(data, 0, coff.RelAMD64Rel32, target)
		if _, err := EmitPICO(object, PICOOptions{}); err == nil || !strings.Contains(err.Error(), "relative relocation in data") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("short ADDR64 site", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		data := testSection(t, object, ".data", 4)
		target := testFunction(t, object, text, "target", 0)
		testRelocation(data, 0, coff.RelAMD64Addr64, target)
		if _, err := EmitPICO(object, PICOOptions{}); err == nil || !strings.Contains(err.Error(), "ADDR64 patch site") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("jump table", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		testSection(t, object, ".text", 4)
		data := testSection(t, object, ".data", 8)
		textSymbol := object.GetSymbol(".text")
		testRelocation(data, 0, coff.RelAMD64Addr64, textSymbol)
		if _, err := EmitPICO(object, PICOOptions{}); err == nil || !strings.Contains(err.Error(), "jump table") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("sparse BSS relocation", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		bss := testSection(t, object, ".bss", 8)
		target := testFunction(t, object, text, "target", 0)
		testRelocation(bss, 0, coff.RelAMD64Addr64, target)
		if _, err := EmitPICO(object, PICOOptions{}); err == nil || !strings.Contains(err.Error(), "sparse .bss") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestEmitPICOExportValidation(t *testing.T) {
	makeObject := func(t *testing.T) *coff.Object {
		t.Helper()
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 8)
		testFunction(t, object, text, "one", 0)
		testFunction(t, object, text, "two", 4)
		testDataSymbol(t, object, text, "notfunc", 0)
		return object
	}
	tests := []struct {
		name    string
		exports []Export
		want    string
	}{
		{name: "reserved", exports: []Export{{Symbol: "one", Tag: 7}}, want: "reserved"},
		{name: "collision", exports: []Export{{Symbol: "one", Tag: 9}, {Symbol: "two", Tag: 9}}, want: "conflicts"},
		{name: "duplicate function and tag", exports: []Export{{Symbol: "one", Tag: 9}, {Symbol: "one", Tag: 9}}, want: "conflicts"},
		{name: "missing", exports: []Export{{Symbol: "missing", Tag: 9}}, want: "does not exist"},
		{name: "not function", exports: []Export{{Symbol: "notfunc", Tag: 9}}, want: "not a function"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := EmitPICO(makeObject(t), PICOOptions{Exports: test.exports}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}
