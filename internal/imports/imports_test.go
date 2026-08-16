// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package imports

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/pe"
)

func TestParseSymbol(t *testing.T) {
	tests := []struct {
		symbol   string
		valid    bool
		module   string
		function string
	}{
		{symbol: "printf"},
		{symbol: "__imp_KERNEL32$Sleep", valid: true, module: "KERNEL32", function: "Sleep"},
		{symbol: "__imp__WS2_32$connect@12", valid: true, module: "WS2_32", function: "connect"},
		{symbol: "__imp_GetProcAddress", valid: true, function: "GetProcAddress"},
		{symbol: "__imp_MOD$func@8@extra", valid: true, module: "MOD", function: "func@8@extra"},
		{symbol: "__imp_MOD$one$two", valid: true, function: "MOD$one$two"},
	}
	for _, test := range tests {
		t.Run(test.symbol, func(t *testing.T) {
			result, valid := ParseSymbol(test.symbol)
			if valid != test.valid || result.Module != test.module || result.Function != test.function {
				t.Fatalf("ParseSymbol(%q) = %#v, %t", test.symbol, result, valid)
			}
		})
	}
}

func TestFromCOFFPreservesRelocationOrderAndDuplicates(t *testing.T) {
	object, err := coff.NewObject(coff.MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", make([]byte, 8))
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	text.Relocations = []*coff.Relocation{
		{Section: text, SymbolName: "__imp_KERNEL32$Sleep"},
		{Section: text, SymbolName: "ordinary"},
		{Section: text, SymbolName: "__imp_KERNEL32$Sleep"},
		{Section: text, SymbolName: "__imp__WS2_32$connect@12"},
	}
	result := FromCOFF(object)
	if got, want := len(result.Imports), 3; got != want {
		t.Fatalf("imports = %d, want %d", got, want)
	}
	if got, want := result.Strings(), []string{"KERNEL32$Sleep", "WS2_32$connect"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Strings() = %#v, want %#v", got, want)
	}
}

func TestFromPENormalizesDLLSuffixAndOrdinal(t *testing.T) {
	object := &pe.Object{Imports: []*pe.Import{
		{Module: "kernel32.DLL", Function: "Sleep"},
		{Module: "user32.dll", ByOrdinal: true, Ordinal: 7},
	}}
	result := FromPE(object)
	if got, want := result.Strings(), []string{"KERNEL32$Sleep", "USER32$(#7)"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Strings() = %#v, want %#v", got, want)
	}
}

func TestParseAutoDetectsCOFF(t *testing.T) {
	fixture := buildImportCOFF()
	result, err := Parse(fixture)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got, want := result.Strings(), []string{"KERNEL32$Sleep"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Strings() = %#v, want %#v", got, want)
	}
	if _, err := Parse([]byte{0xff, 0xff}); err == nil {
		t.Fatal("unknown input unexpectedly parsed")
	}
	if _, err := Parse(nil); err == nil {
		t.Fatal("short input unexpectedly parsed")
	}
}

func buildImportCOFF() []byte {
	const (
		rawPointer        = 60
		relocationPointer = 64
		symbolPointer     = 74
		stringPointer     = symbolPointer + 18
	)
	name := []byte("__imp_KERNEL32$Sleep\x00")
	fixture := make([]byte, stringPointer+4+len(name))
	binary.LittleEndian.PutUint16(fixture[0:2], uint16(coff.MachineAMD64))
	binary.LittleEndian.PutUint16(fixture[2:4], 1)
	binary.LittleEndian.PutUint32(fixture[8:12], symbolPointer)
	binary.LittleEndian.PutUint32(fixture[12:16], 1)
	copy(fixture[20:28], ".text")
	binary.LittleEndian.PutUint32(fixture[36:40], 4)
	binary.LittleEndian.PutUint32(fixture[40:44], rawPointer)
	binary.LittleEndian.PutUint32(fixture[44:48], relocationPointer)
	binary.LittleEndian.PutUint16(fixture[52:54], 1)
	binary.LittleEndian.PutUint32(fixture[56:60], coff.SectionCode|coff.SectionMemRead|coff.SectionMemExecute)
	binary.LittleEndian.PutUint32(fixture[relocationPointer+4:relocationPointer+8], 0)
	binary.LittleEndian.PutUint16(fixture[relocationPointer+8:relocationPointer+10], coff.RelAMD64Rel32)
	binary.LittleEndian.PutUint32(fixture[symbolPointer+4:symbolPointer+8], 4)
	fixture[symbolPointer+16] = coff.SymbolClassExternal
	binary.LittleEndian.PutUint32(fixture[stringPointer:stringPointer+4], uint32(4+len(name)))
	copy(fixture[stringPointer+4:], name)
	return fixture
}
