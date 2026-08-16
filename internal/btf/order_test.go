// SPDX-License-Identifier: GPL-3.0-only

package btf

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestGoFirstAndDiscoRebaseSymbolsAndRelocations(t *testing.T) {
	t.Parallel()
	object := testObject(t)
	// Zeroes make the Fisher-Yates choices deterministic: each iteration swaps
	// with the first eligible chunk.
	random := bytes.NewReader(make([]byte, 32))
	report, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", GoFirst: true, Disco: true, PreserveFirst: true, Random: random})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"go", "helper", "table", "unused"}; !reflect.DeepEqual(report.FinalOrder, want) {
		t.Fatalf("final order = %#v, want %#v", report.FinalOrder, want)
	}
	if got, want := object.GetSection(".text").Data, []byte{0x30, 0, 0, 0, 0, 0x31, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x40, 0x41, 0x10, 0x11}; !bytes.Equal(got, want) {
		t.Fatalf("text = %x, want %x", got, want)
	}
	if got := object.GetSymbol("go").Value; got != 0 {
		t.Fatalf("go value = %d", got)
	}
	if got := object.GetSymbol("helper").Value; got != 6 {
		t.Fatalf("helper value = %d", got)
	}
	if got := object.GetSection(".text").Relocations[0].VirtualAddress; got != 1 {
		t.Fatalf("go relocation = %d", got)
	}
}

func TestOptimizeKeepsReachableFunctionsAndData(t *testing.T) {
	t.Parallel()
	object := testObject(t)
	report, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", Optimize: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"unused"}; !reflect.DeepEqual(report.Removed, want) {
		t.Fatalf("removed = %#v, want %#v", report.Removed, want)
	}
	if object.GetSymbol("unused") != nil {
		t.Fatal("unused symbol remains")
	}
	if got, want := object.GetSection(".text").Data, []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x30, 0, 0, 0, 0, 0x31, 0x40, 0x41}; !bytes.Equal(got, want) {
		t.Fatalf("text = %x, want %x", got, want)
	}
	if got := object.GetSymbol("go").Value; got != 6 {
		t.Fatalf("go value = %d, want 6", got)
	}
}

func TestOptimizeRequiresRoot(t *testing.T) {
	t.Parallel()
	object := testObject(t)
	if _, err := ApplyOrderPasses(object, OrderOptions{Entry: "missing", Optimize: true}); err == nil {
		t.Fatal("ApplyOrderPasses succeeded")
	}
}

func testObject(t *testing.T) *coff.Object {
	t.Helper()
	object, err := coff.NewObject(coff.MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", []byte{0x10, 0x11, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x30, 0, 0, 0, 0, 0x31, 0x40, 0x41})
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	for _, symbol := range []*coff.Symbol{
		coff.NewFunctionSymbol(text, "unused", 0),
		coff.NewFunctionSymbol(text, "helper", 2),
		coff.NewFunctionSymbol(text, "go", 8),
		coff.NewDataSymbol(text, "table", 14),
	} {
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
	}
	// go calls helper. The stored addend is irrelevant to reachability but
	// represents an ordinary REL32 patch site.
	binary.LittleEndian.PutUint32(text.Data[9:13], 0)
	text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 9, SymbolName: "helper", Symbol: object.GetSymbol("helper"), Type: coff.RelAMD64Rel32}}
	return object
}
