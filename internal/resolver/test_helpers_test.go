// SPDX-License-Identifier: GPL-3.0-only

package resolver

import (
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func resolverTestObject(t *testing.T, machine coff.Machine, code []byte) *coff.Object {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	if err := object.AddSection(coff.NewSection(".text", code)); err != nil {
		t.Fatal(err)
	}
	return object
}

func addFunction(t *testing.T, object *coff.Object, section *coff.Section, name string, offset uint32) *coff.Symbol {
	t.Helper()
	symbol := coff.NewFunctionSymbol(section, name, offset)
	if err := object.AddSymbol(symbol); err != nil {
		t.Fatal(err)
	}
	return symbol
}

func addImportRelocation(t *testing.T, object *coff.Object, symbolName string, offset uint32, relocationType uint16) {
	t.Helper()
	text := object.GetSection(".text")
	symbol := object.GetSymbol(symbolName)
	if symbol == nil {
		symbol = &coff.Symbol{Name: symbolName, Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
	}
	text.Relocations = append(text.Relocations, &coff.Relocation{
		Section: text, VirtualAddress: offset, SymbolName: symbolName, Symbol: symbol, Type: relocationType,
	})
}

func defaultConfiguration(t *testing.T, object *coff.Object, function string, method Method) Configuration {
	t.Helper()
	configuration, err := Replay(object, EmptyConfiguration(), []Directive{{Function: function, Method: method, Default: true}})
	if err != nil {
		t.Fatal(err)
	}
	return configuration
}
