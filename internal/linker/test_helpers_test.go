// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"encoding/binary"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func testObject(t testing.TB, machine coff.Machine) *coff.Object {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func testSection(t testing.TB, object *coff.Object, name string, size int) *coff.Section {
	t.Helper()
	section := coff.NewSection(name, make([]byte, size))
	if err := object.AddSection(section); err != nil {
		t.Fatal(err)
	}
	return section
}

func testFunction(t testing.TB, object *coff.Object, section *coff.Section, name string, value uint32) *coff.Symbol {
	t.Helper()
	symbol := coff.NewFunctionSymbol(section, name, value)
	if err := object.AddSymbol(symbol); err != nil {
		t.Fatal(err)
	}
	return symbol
}

func testDataSymbol(t testing.TB, object *coff.Object, section *coff.Section, name string, value uint32) *coff.Symbol {
	t.Helper()
	symbol := coff.NewDataSymbol(section, name, value)
	if err := object.AddSymbol(symbol); err != nil {
		t.Fatal(err)
	}
	return symbol
}

func testUndefined(t testing.TB, object *coff.Object, name string, symbolType uint16) *coff.Symbol {
	t.Helper()
	symbol := &coff.Symbol{Name: name, Type: symbolType, StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(symbol); err != nil {
		t.Fatal(err)
	}
	return symbol
}

func testRelocation(section *coff.Section, address uint32, relocationType uint16, symbol *coff.Symbol) *coff.Relocation {
	relocation := &coff.Relocation{
		Section:        section,
		VirtualAddress: address,
		Type:           relocationType,
		Symbol:         symbol,
		SymbolName:     symbol.Name,
	}
	section.Relocations = append(section.Relocations, relocation)
	return relocation
}

func putTestAddend(t testing.TB, section *coff.Section, address uint32, addend int32) {
	t.Helper()
	if uint64(address)+4 > uint64(len(section.Data)) {
		t.Fatalf("test addend at %#x exceeds section", address)
	}
	binary.LittleEndian.PutUint32(section.Data[address:address+4], uint32(addend))
}

func directiveValue(t testing.TB, directive Directive, index int) uint32 {
	t.Helper()
	offset := index * 4
	if offset+4 > len(directive.Data) {
		t.Fatalf("directive %#x has only %d payload bytes", directive.Type, len(directive.Data))
	}
	return binary.LittleEndian.Uint32(directive.Data[offset : offset+4])
}

func directiveText(t testing.TB, directive Directive) string {
	t.Helper()
	if len(directive.Data) == 0 || directive.Data[len(directive.Data)-1] != 0 {
		t.Fatalf("directive %#x does not contain a NUL-terminated string", directive.Type)
	}
	return string(directive.Data[:len(directive.Data)-1])
}
