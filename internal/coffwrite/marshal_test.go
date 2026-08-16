// SPDX-License-Identifier: GPL-3.0-only

package coffwrite

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestMarshalExactIntelVectors(t *testing.T) {
	tests := []struct {
		name           string
		machine        coff.Machine
		relocationType uint16
		wantHex        string
	}{
		{
			name:           "x86",
			machine:        coff.MachineI386,
			relocationType: coff.RelI386Rel32,
			wantHex:        "4c010100443322114c0000000200000002000400aabb2e74657874000000040000002000000004000000480000003e0000000000000001000000200000600000000001000000140000000000000000000400000000000000010000000300000000000a000000000000000000000002000e0000002e746578740065787400",
		},
		{
			name:           "x64",
			machine:        coff.MachineAMD64,
			relocationType: coff.RelAMD64Rel32,
			wantHex:        "64860100443322114c0000000200000002000400aabb2e74657874000000040000002000000004000000480000003e0000000000000001000000200000600000000001000000040000000000000000000400000000000000010000000300000000000a000000000000000000000002000e0000002e746578740065787400",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object, err := coff.NewObject(test.machine)
			if err != nil {
				t.Fatal(err)
			}
			object.TimeDateStamp = 0x11223344
			object.Characteristics = 0x0004
			object.OptionalHeader = []byte{0xaa, 0xbb}
			text := coff.NewSection(".text", []byte{0, 0, 0, 0})
			text.VirtualSize = 4
			text.VirtualAddress = 0x20
			if err := object.AddSection(text); err != nil {
				t.Fatal(err)
			}
			external := &coff.Symbol{Name: "ext", StorageClass: coff.SymbolClassExternal}
			if err := object.AddSymbol(external); err != nil {
				t.Fatal(err)
			}
			text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 0, SymbolName: external.Name, Symbol: external, Type: test.relocationType}}

			got, err := Marshal(object)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if hex.EncodeToString(got) != test.wantHex {
				t.Fatalf("Marshal() = %s", hex.EncodeToString(got))
			}
			again, err := Marshal(object)
			if err != nil || !bytes.Equal(again, got) {
				t.Fatalf("second Marshal differs: %v", err)
			}
			if _, err := coff.Parse(got); err != nil {
				t.Fatalf("coff.Parse(Marshal()) = %v", err)
			}
		})
	}
}

func TestMarshalRoundTripComplexObject(t *testing.T) {
	for _, test := range []struct {
		name           string
		machine        coff.Machine
		relocationType uint16
	}{
		{name: "x86", machine: coff.MachineI386, relocationType: coff.RelI386Dir32},
		{name: "x64", machine: coff.MachineAMD64, relocationType: coff.RelAMD64Rel32},
	} {
		t.Run(test.name, func(t *testing.T) {
			object, err := coff.NewObject(test.machine)
			if err != nil {
				t.Fatal(err)
			}
			object.TimeDateStamp = 0xa1b2c3d4
			object.Characteristics = 0x0105
			object.OptionalHeader = []byte{1, 2, 3, 4, 5}

			text := coff.NewSection(".text", make([]byte, 8))
			text.VirtualSize = 0x30
			text.VirtualAddress = 0x1000
			text.Alignment = 16
			text.Characteristics |= 0x00500000 // Preserve an IMAGE_SCN_ALIGN flag.
			long := coff.NewSection(".verylong$data", []byte{1, 2, 3, 4})
			long.VirtualSize = 4
			long.VirtualAddress = 0x2000
			long.Alignment = 4
			bss := coff.NewSection(".bss", make([]byte, 19))
			bss.VirtualSize = 32
			bss.VirtualAddress = 0x3000
			bss.Alignment = 8
			for _, section := range []*coff.Section{text, long, bss} {
				if err := object.AddSection(section); err != nil {
					t.Fatal(err)
				}
			}

			sectionAux := bytes.Repeat([]byte{0xa5}, symbolRecordSize)
			object.GetSymbol(".text").AuxiliaryRecords = [][]byte{sectionAux}
			functionAux1 := bytes.Repeat([]byte{0x11}, symbolRecordSize)
			functionAux2 := bytes.Repeat([]byte{0x22}, symbolRecordSize)
			function := coff.NewFunctionSymbol(text, "very_long_function_name", 4)
			function.AuxiliaryRecords = [][]byte{functionAux1, functionAux2}
			undefined := &coff.Symbol{Name: "__imp_KERNEL32$Sleep", StorageClass: coff.SymbolClassExternal}
			absolute := &coff.Symbol{Name: "absolute", Value: 0x55667788, SectionNumber: -1, StorageClass: coff.SymbolClassStatic}
			for _, symbol := range []*coff.Symbol{function, undefined, absolute} {
				if err := object.AddSymbol(symbol); err != nil {
					t.Fatal(err)
				}
			}
			text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 0, Symbol: undefined, SymbolName: undefined.Name, Type: test.relocationType}}
			long.Relocations = []*coff.Relocation{{Section: long, VirtualAddress: 1, Symbol: function, SymbolName: function.Name, Type: test.relocationType}}

			encoded, err := Marshal(object)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			parsed, err := coff.Parse(encoded)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if parsed.Machine != object.Machine || parsed.TimeDateStamp != object.TimeDateStamp || parsed.Characteristics != object.Characteristics || !bytes.Equal(parsed.OptionalHeader, object.OptionalHeader) {
				t.Fatalf("header mismatch: %#v", parsed)
			}
			if len(parsed.Sections) != 3 || parsed.Sections[0].Name != ".text" || parsed.Sections[1].Name != ".verylong$data" || parsed.Sections[2].Name != ".bss" {
				t.Fatalf("section order/names = %#v", parsed.Sections)
			}
			for index, want := range []*coff.Section{text, long, bss} {
				got := parsed.Sections[index]
				if got.VirtualSize != want.VirtualSize || got.VirtualAddress != want.VirtualAddress || got.Characteristics != want.Characteristics || !bytes.Equal(got.Data, want.Data) {
					t.Errorf("section[%d] = %#v, want model fields from %#v", index, got, want)
				}
				if !got.IsUninitialized() && got.PointerToRawData%want.Alignment != 0 {
					t.Errorf("section[%d] raw pointer %#x is not aligned to %d", index, got.PointerToRawData, want.Alignment)
				}
			}
			if parsed.Sections[2].PointerToRawData != 0 || parsed.Sections[2].PointerToRelocations != 0 {
				t.Fatalf("BSS pointers = raw %#x reloc %#x", parsed.Sections[2].PointerToRawData, parsed.Sections[2].PointerToRelocations)
			}

			parsedText := parsed.GetSection(".text")
			parsedLong := parsed.GetSection(".verylong$data")
			if len(parsedText.Relocations) != 1 || parsedText.Relocations[0].SymbolName != undefined.Name {
				t.Fatalf("text relocations = %#v", parsedText.Relocations)
			}
			if len(parsedLong.Relocations) != 1 || parsedLong.Relocations[0].SymbolName != function.Name {
				t.Fatalf("long-section relocations = %#v", parsedLong.Relocations)
			}
			gotSection := parsed.GetSymbol(".text")
			gotFunction := parsed.GetSymbol(function.Name)
			gotUndefined := parsed.GetSymbol(undefined.Name)
			gotAbsolute := parsed.GetSymbol(absolute.Name)
			if gotSection == nil || !reflect.DeepEqual(gotSection.AuxiliaryRecords, [][]byte{sectionAux}) {
				t.Fatalf("section auxiliary records = %#v", gotSection)
			}
			if gotFunction == nil || gotFunction.Section != parsedText || !reflect.DeepEqual(gotFunction.AuxiliaryRecords, [][]byte{functionAux1, functionAux2}) {
				t.Fatalf("function = %#v", gotFunction)
			}
			if gotUndefined == nil || !gotUndefined.IsUndefined() || gotUndefined.SectionNumber != 0 {
				t.Fatalf("undefined symbol = %#v", gotUndefined)
			}
			if gotAbsolute == nil || gotAbsolute.Section != nil || gotAbsolute.SectionNumber != -1 || gotAbsolute.Value != absolute.Value {
				t.Fatalf("absolute symbol = %#v", gotAbsolute)
			}
		})
	}
}

func TestMarshalRecomputesSectionAndSymbolIndices(t *testing.T) {
	object, _ := coff.NewObject(coff.MachineAMD64)
	first := coff.NewSection(".first", []byte{0, 0, 0, 0})
	second := coff.NewSection(".second", []byte{0, 0, 0, 0})
	if err := object.AddSection(first); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSection(second); err != nil {
		t.Fatal(err)
	}
	object.GetSymbol(".first").AuxiliaryRecords = [][]byte{make([]byte, 18), make([]byte, 18)}
	removed := coff.NewDataSymbol(first, "removed", 0)
	target := coff.NewDataSymbol(first, "target", 1)
	if err := object.AddSymbol(removed); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(target); err != nil {
		t.Fatal(err)
	}
	object.RemoveSymbols(map[string]struct{}{"removed": {}})
	object.Sections[0], object.Sections[1] = object.Sections[1], object.Sections[0]
	target.RawIndex = 99
	target.SectionNumber = 99
	second.Relocations = []*coff.Relocation{{Section: second, VirtualAddress: 0, Symbol: target, SymbolName: target.Name, SymbolTableIndex: 77, Type: coff.RelAMD64Addr32NB}}

	encoded, err := Marshal(object)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := coff.Parse(encoded)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	gotTarget := parsed.GetSymbol("target")
	// .second is raw index 0, .first is raw index 1 plus two aux slots,
	// and target follows at raw index 4.
	if gotTarget == nil || gotTarget.RawIndex != 4 || gotTarget.Section != parsed.GetSection(".first") || gotTarget.SectionNumber != 2 {
		t.Fatalf("target after reindex = %#v", gotTarget)
	}
	gotRelocation := parsed.GetSection(".second").Relocations[0]
	if gotRelocation.Symbol != gotTarget || gotRelocation.SymbolTableIndex != 4 {
		t.Fatalf("relocation after reindex = %#v", gotRelocation)
	}
	if target.RawIndex != 99 || target.SectionNumber != 99 || second.Relocations[0].SymbolTableIndex != 77 {
		t.Fatal("Marshal mutated the source model")
	}
}

func TestMarshalPreservesManualLabelRecordForRelocation(t *testing.T) {
	object, _ := coff.NewObject(coff.MachineI386)
	text := coff.NewSection(".text", []byte{0, 0, 0, 0})
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	labelAux := bytes.Repeat([]byte{0x7e}, 18)
	label := &coff.Symbol{Name: "local", Value: 2, Section: text, StorageClass: coff.SymbolClassLabel, AuxiliaryRecords: [][]byte{labelAux}}
	if err := object.AddSymbol(label); err != nil {
		t.Fatal(err)
	}
	text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 0, Symbol: label, SymbolName: label.Name, Type: coff.RelI386Dir32}}
	encoded, err := Marshal(object)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := coff.Parse(encoded)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.GetSymbol("local") != nil {
		t.Fatal("coff.Parse unexpectedly exposed a label in Object.Symbols")
	}
	got := parsed.GetSection(".text").Relocations[0].Symbol
	if got == nil || got.StorageClass != coff.SymbolClassLabel || got.Value != 2 || !reflect.DeepEqual(got.AuxiliaryRecords, [][]byte{labelAux}) {
		t.Fatalf("relocation label = %#v", got)
	}
}

func TestMarshalUsesCOFFNameEncodings(t *testing.T) {
	object, _ := coff.NewObject(coff.MachineAMD64)
	exactEight := coff.NewSection("ABCDEFGH", []byte{0x90})
	long := coff.NewSection("section-name-longer-than-eight", []byte{0xc3})
	if err := object.AddSection(exactEight); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSection(long); err != nil {
		t.Fatal(err)
	}
	longSymbol := coff.NewFunctionSymbol(long, "symbol-name-longer-than-eight", 0)
	if err := object.AddSymbol(longSymbol); err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(object)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := string(encoded[20:28]); got != "ABCDEFGH" {
		t.Fatalf("eight-byte section name = %q", got)
	}
	if got := strings.TrimRight(string(encoded[60:68]), "\x00"); !strings.HasPrefix(got, "/") {
		t.Fatalf("long section name reference = %q", got)
	}
	parsed, err := coff.Parse(encoded)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.GetSection(exactEight.Name) == nil || parsed.GetSection(long.Name) == nil || parsed.GetSymbol(longSymbol.Name) == nil {
		t.Fatalf("long-name round trip failed: %#v", parsed)
	}
}

func TestMarshalRejectsMalformedModels(t *testing.T) {
	valid := func() (*coff.Object, *coff.Section, *coff.Symbol) {
		object, _ := coff.NewObject(coff.MachineAMD64)
		section := coff.NewSection(".text", []byte{0, 0, 0, 0})
		if err := object.AddSection(section); err != nil {
			t.Fatal(err)
		}
		symbol := coff.NewFunctionSymbol(section, "function", 0)
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
		return object, section, symbol
	}
	foreignObject, _ := coff.NewObject(coff.MachineAMD64)
	foreignSection := coff.NewSection(".foreign", []byte{0})
	if err := foreignObject.AddSection(foreignSection); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		model func() *coff.Object
	}{
		{name: "nil object", model: func() *coff.Object { return nil }},
		{name: "unknown machine", model: func() *coff.Object { return &coff.Object{Machine: 0xffff} }},
		{name: "oversized optional header", model: func() *coff.Object {
			object, _, _ := valid()
			object.OptionalHeader = make([]byte, 1<<16)
			return object
		}},
		{name: "nil section", model: func() *coff.Object {
			object, _, _ := valid()
			object.Sections = append(object.Sections, nil)
			return object
		}},
		{name: "empty section name", model: func() *coff.Object {
			object, section, _ := valid()
			section.Name = ""
			section.OriginalName = ""
			return object
		}},
		{name: "NUL section name", model: func() *coff.Object {
			object, section, _ := valid()
			section.OriginalName = "bad\x00name"
			return object
		}},
		{name: "duplicate section pointer", model: func() *coff.Object {
			object, section, _ := valid()
			object.Sections = append(object.Sections, section)
			return object
		}},
		{name: "duplicate serialized section name", model: func() *coff.Object {
			object, _, _ := valid()
			other := coff.NewSection(".other", []byte{1})
			other.OriginalName = ".text"
			object.Sections = append(object.Sections, other)
			return object
		}},
		{name: "foreign section owner", model: func() *coff.Object { object, section, _ := valid(); section.Object = foreignObject; return object }},
		{name: "line number metadata", model: func() *coff.Object { object, section, _ := valid(); section.NumberOfLineNumbers = 1; return object }},
		{name: "non-power-of-two alignment", model: func() *coff.Object { object, section, _ := valid(); section.Alignment = 3; return object }},
		{name: "unsafe alignment allocation", model: func() *coff.Object { object, section, _ := valid(); section.Alignment = 1 << 30; return object }},
		{name: "BSS relocation", model: func() *coff.Object {
			object, section, symbol := valid()
			section.Characteristics |= coff.SectionUninitializedData
			section.Relocations = []*coff.Relocation{{Section: section, Symbol: symbol, SymbolName: symbol.Name}}
			return object
		}},
		{name: "too many relocations", model: func() *coff.Object {
			object, section, _ := valid()
			section.Relocations = make([]*coff.Relocation, 1<<16)
			return object
		}},
		{name: "nil symbol", model: func() *coff.Object {
			object, _, _ := valid()
			object.Symbols = append(object.Symbols, nil)
			return object
		}},
		{name: "empty symbol name", model: func() *coff.Object { object, _, symbol := valid(); symbol.Name = ""; return object }},
		{name: "NUL symbol name", model: func() *coff.Object { object, _, symbol := valid(); symbol.Name = "bad\x00name"; return object }},
		{name: "duplicate symbol pointer", model: func() *coff.Object {
			object, _, symbol := valid()
			object.Symbols = append(object.Symbols, symbol)
			return object
		}},
		{name: "foreign symbol section", model: func() *coff.Object { object, _, symbol := valid(); symbol.Section = foreignSection; return object }},
		{name: "positive number without section", model: func() *coff.Object {
			object, _, symbol := valid()
			symbol.Section = nil
			symbol.SectionNumber = 1
			return object
		}},
		{name: "short auxiliary record", model: func() *coff.Object {
			object, _, symbol := valid()
			symbol.AuxiliaryRecords = [][]byte{{1}}
			return object
		}},
		{name: "too many auxiliary records", model: func() *coff.Object {
			object, _, symbol := valid()
			symbol.AuxiliaryRecords = make([][]byte, 256)
			return object
		}},
		{name: "nil relocation", model: func() *coff.Object {
			object, section, _ := valid()
			section.Relocations = []*coff.Relocation{nil}
			return object
		}},
		{name: "foreign relocation section", model: func() *coff.Object {
			object, section, symbol := valid()
			section.Relocations = []*coff.Relocation{{Section: foreignSection, Symbol: symbol, SymbolName: symbol.Name}}
			return object
		}},
		{name: "relocation outside data", model: func() *coff.Object {
			object, section, symbol := valid()
			section.Relocations = []*coff.Relocation{{Section: section, VirtualAddress: uint32(len(section.Data)), Symbol: symbol, SymbolName: symbol.Name}}
			return object
		}},
		{name: "relocation missing symbol", model: func() *coff.Object {
			object, section, _ := valid()
			section.Relocations = []*coff.Relocation{{Section: section, SymbolName: "missing"}}
			return object
		}},
		{name: "relocation stale symbol pointer", model: func() *coff.Object {
			object, section, _ := valid()
			stale := &coff.Symbol{Name: "stale"}
			section.Relocations = []*coff.Relocation{{Section: section, Symbol: stale, SymbolName: stale.Name}}
			return object
		}},
		{name: "relocation inconsistent name", model: func() *coff.Object {
			object, section, symbol := valid()
			section.Relocations = []*coff.Relocation{{Section: section, Symbol: symbol, SymbolName: "different"}}
			return object
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if output, err := Marshal(test.model()); err == nil {
				t.Fatalf("Marshal succeeded with %d bytes", len(output))
			}
		})
	}
}

func TestMarshalNormalizedCOMDATUsesOriginalName(t *testing.T) {
	object, _ := coff.NewObject(coff.MachineAMD64)
	section := coff.NewSection(".text$mn-0000000000001234", []byte{0x90})
	section.OriginalName = ".text$mn"
	section.Characteristics |= coff.SectionLinkCOMDAT
	if err := object.AddSection(section); err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(object)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsed, err := coff.Parse(encoded)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.Sections) != 1 || parsed.Sections[0].OriginalName != ".text$mn" || !strings.HasPrefix(parsed.Sections[0].Name, ".text$mn-") {
		t.Fatalf("normalized section = %#v", parsed.Sections)
	}
	if parsed.GetSymbol(parsed.Sections[0].Name) == nil {
		t.Fatalf("normalized section symbol missing: %#v", parsed.Symbols)
	}
}

func TestMarshalBSSDoesNotMaterializeContents(t *testing.T) {
	object, _ := coff.NewObject(coff.MachineAMD64)
	bss := coff.NewSection(".bss", make([]byte, 128))
	if err := object.AddSection(bss); err != nil {
		t.Fatal(err)
	}
	encoded, err := Marshal(object)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Header + one section header + one symbol + string table is much smaller
	// than a representation that writes the 128 zero bytes.
	if len(encoded) >= 128 {
		t.Fatalf("BSS was materialized: output size %d", len(encoded))
	}
	if binary.LittleEndian.Uint32(encoded[40:44]) != 0 || binary.LittleEndian.Uint32(encoded[44:48]) != 0 {
		t.Fatalf("BSS file pointers are nonzero: %x", encoded[40:48])
	}
	parsed, err := coff.Parse(encoded)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.GetSection(".bss").Data) != 128 {
		t.Fatalf("parsed BSS size = %d", len(parsed.GetSection(".bss").Data))
	}
}
