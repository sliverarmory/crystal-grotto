// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package coff

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseMinimalIntelCOFF(t *testing.T) {
	for _, test := range []struct {
		name       string
		machine    Machine
		relocation uint16
	}{
		{name: "x86", machine: MachineI386, relocation: RelI386Rel32},
		{name: "x64", machine: MachineAMD64, relocation: RelAMD64Rel32},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := buildCOFFFixture(test.machine, test.relocation)
			object, err := Parse(fixture)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if object.Machine != test.machine || object.Architecture() != test.name {
				t.Fatalf("machine = %v/%q, want %v/%q", object.Machine, object.Architecture(), test.machine, test.name)
			}
			if len(object.Sections) != 1 || object.Sections[0].Name != ".text" {
				t.Fatalf("sections = %#v", object.Sections)
			}
			text := object.GetSection(".text")
			if got, want := len(text.Data), 5; got != want {
				t.Fatalf("text size = %d, want %d", got, want)
			}
			if got, want := len(object.Symbols), 3; got != want {
				t.Fatalf("symbols = %d, want %d", got, want)
			}
			sectionSymbol := object.GetSymbol(".text")
			if sectionSymbol == nil || len(sectionSymbol.AuxiliaryRecords) != 1 || !sectionSymbol.IsSectionName() {
				t.Fatalf("section symbol = %#v", sectionSymbol)
			}
			imported := object.GetSymbol("__imp_KERNEL32$Sleep")
			if imported == nil || !imported.IsUndefined() || !imported.IsExternal() {
				t.Fatalf("import symbol = %#v", imported)
			}
			entry := object.GetSymbol("entry")
			if entry == nil || !entry.IsFunction() || entry.Section != text {
				t.Fatalf("entry symbol = %#v", entry)
			}
			if len(text.Relocations) != 1 {
				t.Fatalf("relocations = %d", len(text.Relocations))
			}
			relocation := text.Relocations[0]
			if relocation.Symbol != imported || relocation.SymbolName != imported.Name || relocation.Type != test.relocation {
				t.Fatalf("relocation = %#v", relocation)
			}
			offset, err := relocation.Offset()
			if err != nil || offset != 0 {
				t.Fatalf("Offset() = %d, %v", offset, err)
			}
			// Parsed bytes must not alias caller-owned input.
			fixture[text.PointerToRawData] = 0xff
			if text.Data[0] != 0 {
				t.Fatal("section data aliases parser input")
			}
			first := object.String()
			if second := object.String(); second != first {
				t.Fatalf("String() is nondeterministic:\n%s\n---\n%s", first, second)
			}
			if !strings.Contains(first, "__imp_KERNEL32$Sleep") {
				t.Fatalf("String() omitted import:\n%s", first)
			}
		})
	}
}

func TestParseUninitializedSection(t *testing.T) {
	fixture := make([]byte, 20+40+4)
	binary.LittleEndian.PutUint16(fixture[0:2], uint16(MachineAMD64))
	binary.LittleEndian.PutUint16(fixture[2:4], 1)
	binary.LittleEndian.PutUint32(fixture[8:12], 60)
	copy(fixture[20:28], ".bss")
	binary.LittleEndian.PutUint32(fixture[36:40], 16)
	binary.LittleEndian.PutUint32(fixture[56:60], SectionUninitializedData|SectionMemRead|SectionMemWrite)
	binary.LittleEndian.PutUint32(fixture[60:64], 4)

	object, err := Parse(fixture)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	section := object.GetSection(".bss")
	if section == nil || len(section.Data) != 16 || !section.IsUninitialized() {
		t.Fatalf("section = %#v", section)
	}
	for _, value := range section.Data {
		if value != 0 {
			t.Fatalf("uninitialized section contains %#x", value)
		}
	}
}

func TestParseLongCOMDATSectionName(t *testing.T) {
	const rawPointer = 60
	name := []byte(".text$mn\x00")
	fixture := make([]byte, rawPointer+1+4+len(name))
	binary.LittleEndian.PutUint16(fixture[0:2], uint16(MachineAMD64))
	binary.LittleEndian.PutUint16(fixture[2:4], 1)
	binary.LittleEndian.PutUint32(fixture[8:12], rawPointer+1)
	copy(fixture[20:28], "/4")
	binary.LittleEndian.PutUint32(fixture[36:40], 1)
	binary.LittleEndian.PutUint32(fixture[40:44], rawPointer)
	binary.LittleEndian.PutUint32(fixture[56:60], SectionCode|SectionMemRead|SectionMemExecute|SectionLinkCOMDAT)
	binary.LittleEndian.PutUint32(fixture[rawPointer+1:rawPointer+5], uint32(4+len(name)))
	copy(fixture[rawPointer+5:], name)

	object, err := Parse(fixture)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	want := ".text$mn-000000000000003C"
	if len(object.Sections) != 1 || object.Sections[0].Name != want || object.Sections[0].OriginalName != ".text$mn" {
		t.Fatalf("section = %#v, want normalized name %q", object.Sections, want)
	}
}

func TestObjectMutationHelpers(t *testing.T) {
	object, err := NewObject(MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	text := NewSection(".text", make([]byte, 8))
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	function := NewFunctionSymbol(text, "old", 0)
	if err := object.AddSymbol(function); err != nil {
		t.Fatal(err)
	}
	text.Relocations = []*Relocation{{Section: text, Symbol: function, SymbolName: "old"}}
	if err := object.RemapSymbol("old", "new"); err != nil {
		t.Fatal(err)
	}
	if object.GetSymbol("old") != nil || object.GetSymbol("new") != function || text.Relocations[0].SymbolName != "new" {
		t.Fatal("RemapSymbol did not update indexes and relocations")
	}
	if err := text.Patch(6, []byte{1, 2}); err != nil {
		t.Fatal(err)
	}
	if err := text.Patch(7, []byte{1, 2}); err == nil {
		t.Fatal("out-of-range patch unexpectedly succeeded")
	}
}

func TestParseRejectsMalformedCOFF(t *testing.T) {
	valid := buildCOFFFixture(MachineAMD64, RelAMD64Rel32)
	tests := []struct {
		name string
		data func() []byte
	}{
		{name: "empty", data: func() []byte { return nil }},
		{name: "unknown machine", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint16(value[:2], 0xffff)
			return value
		}},
		{name: "truncated section table", data: func() []byte { return append([]byte(nil), valid[:40]...) }},
		{name: "raw data out of bounds", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(value[40:44], uint32(len(value)+1))
			return value
		}},
		{name: "symbol table out of bounds", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(value[8:12], uint32(len(value)-1))
			return value
		}},
		{name: "aux symbol relocation", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(value[69:73], 1)
			return value
		}},
		{name: "unterminated long symbol", data: func() []byte {
			value := append([]byte(nil), valid...)
			value[len(value)-1] = 'X'
			return value
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(test.data()); err == nil {
				t.Fatal("Parse() unexpectedly succeeded")
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add(buildCOFFFixture(MachineI386, RelI386Rel32))
	f.Add(buildCOFFFixture(MachineAMD64, RelAMD64Rel32))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
	})
}

func buildCOFFFixture(machine Machine, relocationType uint16) []byte {
	const (
		rawPointer        = 60
		rawSize           = 5
		relocationPointer = rawPointer + rawSize
		symbolPointer     = relocationPointer + 10
		numberOfSymbols   = 4 // section, its auxiliary record, import, entry
		stringPointer     = symbolPointer + numberOfSymbols*18
	)
	longName := []byte("__imp_KERNEL32$Sleep\x00")
	fixture := make([]byte, stringPointer+4+len(longName))
	binary.LittleEndian.PutUint16(fixture[0:2], uint16(machine))
	binary.LittleEndian.PutUint16(fixture[2:4], 1)
	binary.LittleEndian.PutUint32(fixture[8:12], symbolPointer)
	binary.LittleEndian.PutUint32(fixture[12:16], numberOfSymbols)

	copy(fixture[20:28], ".text")
	binary.LittleEndian.PutUint32(fixture[36:40], rawSize)
	binary.LittleEndian.PutUint32(fixture[40:44], rawPointer)
	binary.LittleEndian.PutUint32(fixture[44:48], relocationPointer)
	binary.LittleEndian.PutUint16(fixture[52:54], 1)
	binary.LittleEndian.PutUint32(fixture[56:60], SectionCode|SectionMemExecute|SectionMemRead)
	copy(fixture[rawPointer:rawPointer+rawSize], []byte{0, 0, 0, 0, 0xc3})

	binary.LittleEndian.PutUint32(fixture[relocationPointer:relocationPointer+4], 0)
	binary.LittleEndian.PutUint32(fixture[relocationPointer+4:relocationPointer+8], 2)
	binary.LittleEndian.PutUint16(fixture[relocationPointer+8:relocationPointer+10], relocationType)

	sectionSymbol := fixture[symbolPointer : symbolPointer+18]
	copy(sectionSymbol[:8], ".text")
	binary.LittleEndian.PutUint16(sectionSymbol[12:14], 1)
	sectionSymbol[16] = SymbolClassStatic
	sectionSymbol[17] = 1

	importSymbol := fixture[symbolPointer+36 : symbolPointer+54]
	binary.LittleEndian.PutUint32(importSymbol[4:8], 4)
	importSymbol[16] = SymbolClassExternal

	entrySymbol := fixture[symbolPointer+54 : symbolPointer+72]
	copy(entrySymbol[:8], "entry")
	binary.LittleEndian.PutUint16(entrySymbol[12:14], 1)
	binary.LittleEndian.PutUint16(entrySymbol[14:16], SymbolTypeFunction)
	entrySymbol[16] = SymbolClassExternal

	binary.LittleEndian.PutUint32(fixture[stringPointer:stringPointer+4], uint32(4+len(longName)))
	copy(fixture[stringPointer+4:], longName)
	return fixture
}
