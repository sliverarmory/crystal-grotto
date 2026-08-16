// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package coff

import (
	"errors"
	"reflect"
	"testing"
)

func TestMachineAndParseError(t *testing.T) {
	for _, test := range []struct {
		machine Machine
		name    string
		bits    int
	}{
		{MachineI386, "x86", 32},
		{MachineAMD64, "x64", 64},
		{MachineARM64, "arm64", 64},
	} {
		bits, err := test.machine.Bits()
		if err != nil || bits != test.bits || test.machine.String() != test.name || !test.machine.Valid() {
			t.Fatalf("machine %#x = %q/%d/%v", test.machine, test.machine.String(), bits, err)
		}
		parsed, err := ParseMachine([]byte{byte(test.machine), byte(test.machine >> 8)})
		if err != nil || parsed != test.machine {
			t.Fatalf("ParseMachine(%v) = %v, %v", test.machine, parsed, err)
		}
	}
	unknown := Machine(0xffff)
	if unknown.Valid() || unknown.String() != "unknown-0xffff" {
		t.Fatalf("unexpected unknown machine behavior: %q", unknown.String())
	}
	if _, err := unknown.Bits(); err == nil {
		t.Fatal("unknown machine returned a bit width")
	}
	if _, err := ParseMachine([]byte{0xff, 0xff}); err == nil {
		t.Fatal("unknown ParseMachine input succeeded")
	}
	if _, err := ParseMachine(nil); err == nil {
		t.Fatal("short ParseMachine input succeeded")
	}
	cause := errors.New("bad")
	err := &ParseError{Offset: 4, Context: "thing", Err: cause}
	if !errors.Is(err, cause) || err.Error() != "coff: thing at offset 0x4: bad" {
		t.Fatalf("ParseError = %q", err)
	}
}

func TestSectionSymbolAndRelocationHelpers(t *testing.T) {
	object, _ := NewObject(MachineAMD64)
	text := NewSection(".text$one", make([]byte, 32))
	text.Characteristics = FlagsForName(".text") | SectionLinkCOMDAT
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	first := NewFunctionSymbol(text, "first", 0)
	second := NewFunctionSymbol(text, "second", 16)
	data := NewDataSymbol(text, "global", 24)
	for _, symbol := range []*Symbol{second, data, first} {
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
	}
	if !object.IsIntel() || !object.IsX64() || object.IsX86() {
		t.Fatal("architecture helpers disagree")
	}
	bits, err := object.Bits()
	if err != nil || bits != 64 {
		t.Fatalf("Bits() = %d, %v", bits, err)
	}
	if text.GroupName() != ".text" || !text.IsExecutable() || !text.IsCOMDAT() || text.IsUninitialized() {
		t.Fatalf("section helpers disagree: %s", FormatSectionFlags(text.Characteristics))
	}
	if !data.IsGlobalVariable() || first.IsGlobalVariable() || !first.FoldsWith(NewFunctionSymbol(text, "first", 100)) {
		t.Fatal("symbol helpers disagree")
	}
	if first.EstimateSize() != 16 || second.EstimateSize() != 8 || data.EstimateSize() != 8 {
		t.Fatalf("symbol sizes = %d, %d, %d", first.EstimateSize(), second.EstimateSize(), data.EstimateSize())
	}

	text.Data[20] = 4
	relocation := &Relocation{Section: text, VirtualAddress: 20, Symbol: second, SymbolName: second.Name, Type: RelAMD64Rel32}
	text.Relocations = []*Relocation{relocation}
	if !relocation.IsAMD64Rel32() || relocation.FromOffset() != 4 || relocation.RemoteSection() != text {
		t.Fatal("relocation helpers disagree")
	}
	remote, err := relocation.RemoteSectionOffset()
	if err != nil || remote != 20 {
		t.Fatalf("RemoteSectionOffset() = %d, %v", remote, err)
	}
	if function := relocation.ContainingFunction(); function != second {
		t.Fatalf("ContainingFunction() = %#v", function)
	}
	missing := &Relocation{Section: text, SymbolName: "missing"}
	if missing.RemoteSection() != nil {
		t.Fatal("missing relocation has a remote section")
	}
	if _, err := missing.RemoteSectionOffset(); err == nil {
		t.Fatal("missing relocation returned a remote offset")
	}
	badOffset := &Relocation{Section: text, VirtualAddress: 31}
	if _, err := badOffset.Offset(); err == nil {
		t.Fatal("out-of-range relocation offset succeeded")
	}

	fetched, err := text.Fetch(20, 4)
	if err != nil || !reflect.DeepEqual(fetched, []byte{4, 0, 0, 0}) {
		t.Fatalf("Fetch() = %v, %v", fetched, err)
	}
	if _, err := text.Fetch(31, 2); err == nil {
		t.Fatal("out-of-range Fetch succeeded")
	}
	if text.PagePadding() != 4096-32 || len(text.PageAlignedData()) != 4096 {
		t.Fatal("page alignment helpers disagree")
	}
	page := NewSection(".rdata", make([]byte, 4096))
	if page.PagePadding() != 4096 || len(page.PageAlignedData()) != 8192 {
		t.Fatal("historical full-page padding behavior was not retained")
	}
}

func TestFlagsForAllConventionalSections(t *testing.T) {
	tests := map[string]uint32{
		".text":  SectionCode | SectionMemExecute | SectionMemRead,
		".rdata": SectionInitializedData | SectionMemRead,
		".data":  SectionInitializedData | SectionMemRead | SectionMemWrite,
		".bss":   SectionUninitializedData | SectionMemRead | SectionMemWrite,
		".other": SectionInitializedData | SectionMemRead,
	}
	for name, want := range tests {
		if got := FlagsForName(name); got != want {
			t.Fatalf("FlagsForName(%q) = %#x, want %#x", name, got, want)
		}
	}
	formatted := FormatSectionFlags(SectionCode | SectionInitializedData | SectionUninitializedData | SectionLinkCOMDAT | SectionMemRead | SectionMemWrite | SectionMemExecute)
	if formatted != "rwx (code) (init) (not init) (COMDAT)" {
		t.Fatalf("FormatSectionFlags() = %q", formatted)
	}
}

func TestWalkAndRemoveSymbols(t *testing.T) {
	object, _ := NewObject(MachineI386)
	text := NewSection(".text", make([]byte, 4))
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	function := NewFunctionSymbol(text, "function", 0)
	if err := object.AddSymbol(function); err != nil {
		t.Fatal(err)
	}
	text.Relocations = []*Relocation{{Section: text, Symbol: function, SymbolName: function.Name, Type: RelI386Rel32}}
	var events []string
	err := object.Walk(Visitor{
		Section: func(section *Section) error {
			events = append(events, "section:"+section.Name)
			return nil
		},
		Relocation: func(_ *Section, relocation *Relocation) error {
			events = append(events, "relocation:"+relocation.SymbolName)
			return nil
		},
		Symbol: func(symbol *Symbol) error {
			events = append(events, "symbol:"+symbol.Name)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"section:.text", "relocation:function", "symbol:.text", "symbol:function"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
	stop := errors.New("stop")
	if err := object.Walk(Visitor{Section: func(*Section) error { return stop }}); !errors.Is(err, stop) {
		t.Fatalf("Walk error = %v", err)
	}
	object.RemoveSymbols(map[string]struct{}{"function": {}})
	if object.GetSymbol("function") != nil || len(object.Symbols) != 1 {
		t.Fatal("RemoveSymbols did not update slice and index")
	}
	if err := object.AddSection(NewSection(".text", nil)); err == nil {
		t.Fatal("duplicate section succeeded")
	}
	if err := object.AddSymbol(NewSectionSymbol(text, ".text")); err == nil {
		t.Fatal("duplicate symbol succeeded")
	}
}

func TestUnwindOperationNamesAndValues(t *testing.T) {
	operations := []uint8{UnwindOpPushNonVol, UnwindOpAllocLarge, UnwindOpAllocSmall, UnwindOpSetFPReg, UnwindOpSaveNonVol, UnwindOpSaveNonVolFar, UnwindOpSaveXMM128, UnwindOpSaveXMM128Far, UnwindOpPushMachFrame, 15}
	for _, operation := range operations {
		if (UnwindCode{Operation: operation}).OperationName() == "" {
			t.Fatalf("operation %d has no name", operation)
		}
	}
	if RegisterName(16) != "unknown" {
		t.Fatal("invalid register was not reported as unknown")
	}
	if got := unwindValue(UnwindCode{Operation: UnwindOpAllocSmall, OpInfo: 3}); got != 32 {
		t.Fatalf("small allocation = %d", got)
	}
	if got := unwindValue(UnwindCode{Operation: UnwindOpSaveXMM128, RawExtra: []uint16{2}}); got != 32 {
		t.Fatalf("XMM save offset = %d", got)
	}
	if got := unwindValue(UnwindCode{Operation: UnwindOpSaveNonVolFar, RawExtra: []uint16{0x5678, 0x1234}}); got != 0x12345678 {
		t.Fatalf("far save offset = %#x", got)
	}
}
