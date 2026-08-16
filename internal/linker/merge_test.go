// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestMergeLayoutSymbolsAndRelocations(t *testing.T) {
	first := testObject(t, coff.MachineAMD64)
	firstText := testSection(t, first, ".text", 12)
	testFunction(t, first, firstText, "go", 0)

	second := testObject(t, coff.MachineAMD64)
	secondText := testSection(t, second, ".text$helper", 4)
	secondText.Alignment = 8
	helper := testFunction(t, second, secondText, "helper", 0)
	secondData := testSection(t, second, ".data$item", 4)
	global := testDataSymbol(t, second, secondData, "global", 0)

	// The helper becomes colocated after merge and is fully resolved. The data
	// reference remains for the PIC/PICO exporter.
	testRelocation(firstText, 4, coff.RelAMD64Rel32, helper)
	testRelocation(firstText, 8, coff.RelAMD64Rel32, global)

	merged, err := Merge(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(merged.Sections), 4; got != want {
		t.Fatalf("section count = %d, want %d", got, want)
	}
	text := merged.GetSection(".text")
	if got, want := len(text.Data), 20; got != want {
		t.Fatalf("merged .text length = %d, want %d", got, want)
	}
	if got := merged.GetSymbol("helper").Value; got != 16 {
		t.Fatalf("helper offset = %d, want 16", got)
	}
	if got := int32(binary.LittleEndian.Uint32(text.Data[4:8])); got != 8 {
		t.Fatalf("resolved helper displacement = %d, want 8", got)
	}
	if got, want := len(text.Relocations), 1; got != want {
		t.Fatalf("remaining relocations = %d, want %d", got, want)
	}
	if text.Relocations[0].Symbol != merged.GetSymbol("global") || text.Relocations[0].VirtualAddress != 8 {
		t.Fatalf("data relocation was not retained and rebound: %#v", text.Relocations[0])
	}
	for index, name := range []string{".text", ".rdata", ".data", ".bss"} {
		if merged.Sections[index].Name != name {
			t.Fatalf("section %d = %q, want %q", index, merged.Sections[index].Name, name)
		}
	}
}

func TestMergeSectionSymbolRebasesAddend(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 8)
	first := testSection(t, object, ".rdata$A", 4)
	second := testSection(t, object, ".rdata$B", 4)
	second.Alignment = 8
	sectionSymbol := object.GetSymbol(second.Name)
	// Dependency-walk order is significant upstream. Visit the first subsection
	// before the aligned second subsection so the latter has a non-zero base.
	firstSymbol := testDataSymbol(t, object, first, "first", 0)
	testRelocation(text, 0, coff.RelAMD64Addr32NB, firstSymbol)
	putTestAddend(t, text, 4, 2)
	testRelocation(text, 4, coff.RelAMD64Addr32NB, sectionSymbol)

	merged, err := Merge(object)
	if err != nil {
		t.Fatal(err)
	}
	mergedText := merged.GetSection(".text")
	if got := binary.LittleEndian.Uint32(mergedText.Data[4:8]); got != 10 {
		t.Fatalf("rebased section addend = %d, want 10", got)
	}
	if got := mergedText.Relocations[1].SymbolName; got != ".rdata" {
		t.Fatalf("section relocation target = %q, want .rdata", got)
	}
}

func TestMergeCOMDATFolding(t *testing.T) {
	first := testObject(t, coff.MachineAMD64)
	firstText := testSection(t, first, ".text$first", 4)
	firstText.Characteristics |= coff.SectionLinkCOMDAT
	firstText.Data[0] = 0xaa
	testFunction(t, first, firstText, "folded", 0)

	second := testObject(t, coff.MachineAMD64)
	secondText := testSection(t, second, ".text$second", 4)
	secondText.Characteristics |= coff.SectionLinkCOMDAT
	secondText.Data[0] = 0xbb
	testFunction(t, second, secondText, "folded", 0)

	merged, err := Merge(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := merged.GetSection(".text").Data, []byte{0xaa, 0, 0, 0}; string(got) != string(want) {
		t.Fatalf("folded data = %x, want %x", got, want)
	}
	if merged.GetSymbol("folded") == nil {
		t.Fatal("folded definition was lost")
	}
}

func TestMergeSkipsAlreadyRepresentedObject(t *testing.T) {
	first := testObject(t, coff.MachineAMD64)
	firstText := testSection(t, first, ".text$first", 4)
	firstText.Data[0] = 0xaa
	testFunction(t, first, firstText, "represented", 0)

	second := testObject(t, coff.MachineAMD64)
	secondText := testSection(t, second, ".text$second", 4)
	secondText.Data[0] = 0xbb
	testFunction(t, second, secondText, "represented", 0)

	merged, err := Merge(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := merged.GetSection(".text").Data, []byte{0xaa, 0, 0, 0}; string(got) != string(want) {
		t.Fatalf("represented object data = %x, want %x", got, want)
	}
}

func TestMergeRDataZZZOnlyWhenReferenced(t *testing.T) {
	build := func(t *testing.T, referenced bool) *coff.Object {
		t.Helper()
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		zzz := testSection(t, object, ".rdata$zzz", 3)
		copy(zzz.Data, "zzz")
		symbol := testDataSymbol(t, object, zzz, "late", 0)
		if referenced {
			testRelocation(text, 0, coff.RelAMD64Addr32NB, symbol)
		}
		return object
	}

	without, err := Merge(build(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(without.GetSection(".rdata").Data); got != 0 {
		t.Fatalf("unreferenced .rdata$zzz contributed %d bytes", got)
	}
	with, err := Merge(build(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(with.GetSection(".rdata").Data); got != "zzz" {
		t.Fatalf("referenced .rdata$zzz = %q, want zzz", got)
	}
}

func TestMergeRejectsInvalidInputs(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		if _, err := Merge(); err == nil {
			t.Fatal("Merge() succeeded")
		}
	})
	t.Run("machine mismatch", func(t *testing.T) {
		if _, err := Merge(testObject(t, coff.MachineAMD64), testObject(t, coff.MachineI386)); err == nil || !strings.Contains(err.Error(), "machine mismatch") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("duplicate external", func(t *testing.T) {
		first := testObject(t, coff.MachineAMD64)
		second := testObject(t, coff.MachineAMD64)
		testFunction(t, first, testSection(t, first, ".text", 1), "same", 0)
		secondText := testSection(t, second, ".text", 2)
		testFunction(t, second, secondText, "same", 0)
		testFunction(t, second, secondText, "new", 1)
		if _, err := Merge(first, second); err == nil || !strings.Contains(err.Error(), "duplicate external") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("relocation bounds", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		target := testFunction(t, object, text, "target", 0)
		testRelocation(text, 3, coff.RelAMD64Rel32, target)
		if _, err := Merge(object); err == nil || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestMergeLibraryFixedPointSelection(t *testing.T) {
	base := testObject(t, coff.MachineAMD64)
	baseText := testSection(t, base, ".text", 4)
	fooUndefined := testUndefined(t, base, "foo", coff.SymbolTypeFunction)
	testRelocation(baseText, 0, coff.RelAMD64Rel32, fooUndefined)

	fooObject := testObject(t, coff.MachineAMD64)
	fooText := testSection(t, fooObject, ".text$foo", 4)
	testFunction(t, fooObject, fooText, "foo", 0)
	barUndefined := testUndefined(t, fooObject, "bar", coff.SymbolTypeFunction)
	testRelocation(fooText, 0, coff.RelAMD64Rel32, barUndefined)

	barObject := testObject(t, coff.MachineAMD64)
	barText := testSection(t, barObject, ".text$bar", 4)
	testFunction(t, barObject, barText, "bar", 0)

	unusedObject := testObject(t, coff.MachineAMD64)
	testFunction(t, unusedObject, testSection(t, unusedObject, ".text$unused", 1), "unused", 0)

	merged, selected, err := MergeLibrary(base, []LibraryMember{
		{Name: "bar.obj", Object: barObject}, // requires a second pass
		{Name: "foo.obj", Object: fooObject},
		{Name: "unused.obj", Object: unusedObject},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(selected, ","), "foo.obj,bar.obj"; got != want {
		t.Fatalf("selected = %q, want %q", got, want)
	}
	if merged.GetSymbol("foo") == nil || merged.GetSymbol("bar") == nil {
		t.Fatalf("selected definitions missing: %v", merged.Symbols)
	}
	if merged.GetSymbol("unused") != nil {
		t.Fatal("unused library member was merged")
	}
}

func TestMergeLibraryDoesNotSelectForDefinedLocal(t *testing.T) {
	base := testObject(t, coff.MachineAMD64)
	text := testSection(t, base, ".text", 4)
	local := &coff.Symbol{Name: "local", Section: text, StorageClass: coff.SymbolClassStatic}
	if err := base.AddSymbol(local); err != nil {
		t.Fatal(err)
	}
	testRelocation(text, 0, coff.RelAMD64Rel32, local)

	member := testObject(t, coff.MachineAMD64)
	testFunction(t, member, testSection(t, member, ".text", 1), "local", 0)
	_, selected, err := MergeLibrary(base, []LibraryMember{{Name: "wrong.obj", Object: member}})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 0 {
		t.Fatalf("selected local-symbol member: %v", selected)
	}
}

func TestMergeResolvesX86REL32(t *testing.T) {
	object := testObject(t, coff.MachineI386)
	text := testSection(t, object, ".text", 8)
	target := testFunction(t, object, text, "target", 4)
	testRelocation(text, 0, coff.RelI386Rel32, target)
	merged, err := Merge(object)
	if err != nil {
		t.Fatal(err)
	}
	if got := int32(binary.LittleEndian.Uint32(merged.GetSection(".text").Data[:4])); got != 0 {
		t.Fatalf("x86 displacement = %d, want 0", got)
	}
	if len(merged.GetSection(".text").Relocations) != 0 {
		t.Fatal("x86 same-section REL32 was retained")
	}
}
