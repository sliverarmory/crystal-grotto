// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestEmitPICAMD64(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 8)
	rdata := testSection(t, object, ".rdata", 4)
	testFunction(t, object, text, "go", 0)
	constant := testDataSymbol(t, object, rdata, "constant", 0)
	testRelocation(text, 0, coff.RelAMD64Rel32, constant)
	testRelocation(text, 4, coff.RelAMD64Addr32NB, constant)

	image, err := EmitPIC(object, PICOptions{RequireEntry: true})
	if err != nil {
		t.Fatal(err)
	}
	if !image.HasEntry || image.EntryOffset != 0 {
		t.Fatalf("entry = (%v, %#x)", image.HasEntry, image.EntryOffset)
	}
	if got := int32(binary.LittleEndian.Uint32(image.Bytes[:4])); got != 4 {
		t.Fatalf("REL32 displacement = %d, want 4", got)
	}
	if got := binary.LittleEndian.Uint32(image.Bytes[4:8]); got != 8 {
		t.Fatalf("ADDR32NB offset = %d, want 8", got)
	}
	if got, want := len(image.Bytes), 12; got != want {
		t.Fatalf("image length = %d, want %d", got, want)
	}
}

func TestEmitPICLinkedSection(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 4)
	testFunction(t, object, text, "go", 0)
	helper := testUndefined(t, object, "helper", coff.SymbolTypeFunction)
	testRelocation(text, 0, coff.RelAMD64Rel32, helper)

	image, err := EmitPIC(object, PICOptions{Links: []LinkedSection{{Name: "helper", Data: []byte{0xcc}, Executable: true, Alignment: 8}}})
	if err != nil {
		t.Fatal(err)
	}
	placement, ok := image.Layout.SectionPlacement("helper")
	if !ok || placement.Offset != 8 {
		t.Fatalf("helper placement = %#v, %v", placement, ok)
	}
	if got := int32(binary.LittleEndian.Uint32(image.Bytes[:4])); got != 4 {
		t.Fatalf("helper displacement = %d, want 4", got)
	}
}

func TestEmitPICLinkedSectionRelocations(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 4)
	testFunction(t, object, text, "go", 0)

	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], 1)
	binary.LittleEndian.PutUint32(data[4:8], 2)
	image, err := EmitPIC(object, PICOptions{Links: []LinkedSection{{
		Name: "unwind", Data: data, Alignment: 4,
		Relocations: []LinkedRelocation{
			{VirtualAddress: 0, SymbolName: ".text", Type: coff.RelAMD64Addr32NB},
			{VirtualAddress: 4, SymbolName: "unwind", Type: coff.RelAMD64Addr32NB},
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	placement, ok := image.Layout.SectionPlacement("unwind")
	if !ok || placement.Offset != 4 {
		t.Fatalf("unwind placement = %#v, %v", placement, ok)
	}
	if got := binary.LittleEndian.Uint32(image.Bytes[4:8]); got != 1 {
		t.Fatalf(".text relocation = %#x, want 1", got)
	}
	if got := binary.LittleEndian.Uint32(image.Bytes[8:12]); got != 6 {
		t.Fatalf("self relocation = %#x, want 6", got)
	}
}

func TestEmitPICRejectsInvalidLinkedRelocation(t *testing.T) {
	object := testObject(t, coff.MachineAMD64)
	text := testSection(t, object, ".text", 1)
	testFunction(t, object, text, "go", 0)
	_, err := EmitPIC(object, PICOptions{Links: []LinkedSection{{
		Name: "bad", Data: make([]byte, 4),
		Relocations: []LinkedRelocation{{VirtualAddress: 1, SymbolName: ".text", Type: coff.RelAMD64Addr32NB}},
	}}})
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("invalid linked relocation error = %v", err)
	}
}

func TestEmitPICX86Relocations(t *testing.T) {
	makeObject := func(t *testing.T, relocationType uint16) *coff.Object {
		t.Helper()
		object := testObject(t, coff.MachineI386)
		text := testSection(t, object, ".text", 4)
		testFunction(t, object, text, "_go", 0)
		target := testUndefined(t, object, "target", 0)
		testRelocation(text, 0, relocationType, target)
		return object
	}

	link := []LinkedSection{{Name: "target", Data: []byte{0}, Alignment: 1}}
	image, err := EmitPIC(makeObject(t, coff.RelI386Rel32), PICOptions{Links: link})
	if err != nil {
		t.Fatal(err)
	}
	if got := int32(binary.LittleEndian.Uint32(image.Bytes[:4])); got != 0 {
		t.Fatalf("x86 REL32 displacement = %d, want 0", got)
	}
	if _, err := EmitPIC(makeObject(t, coff.RelI386Dir32), PICOptions{Links: link}); err == nil || !strings.Contains(err.Error(), "X86RelativeDIR32") {
		t.Fatalf("DIR32 error = %v", err)
	}
	image, err = EmitPIC(makeObject(t, coff.RelI386Dir32), PICOptions{Links: link, X86RelativeDIR32: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := int32(binary.LittleEndian.Uint32(image.Bytes[:4])); got != 0 {
		t.Fatalf("relative DIR32 displacement = %d, want 0", got)
	}
}

func TestEmitPICRejectsEntryAndRelocationErrors(t *testing.T) {
	t.Run("nonzero entry", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 8)
		testFunction(t, object, text, "go", 1)
		if _, err := EmitPIC(object, PICOptions{}); err == nil || !strings.Contains(err.Error(), "not zero") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("missing required entry", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		testSection(t, object, ".text", 1)
		if _, err := EmitPIC(object, PICOptions{RequireEntry: true}); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("ADDR64", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 8)
		testFunction(t, object, text, "go", 0)
		target := testFunction(t, object, text, "target", 4)
		testRelocation(text, 0, coff.RelAMD64Addr64, target)
		if _, err := EmitPIC(object, PICOptions{}); err == nil || !strings.Contains(err.Error(), "ADDR64") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("rdata relocation", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		rdata := testSection(t, object, ".rdata", 8)
		testFunction(t, object, text, "go", 0)
		target := testFunction(t, object, text, "target", 0)
		testRelocation(rdata, 0, coff.RelAMD64Addr64, target)
		if _, err := EmitPIC(object, PICOptions{}); err == nil || !strings.Contains(err.Error(), "ADDR64 in .rdata") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("x86 rdata relocation", func(t *testing.T) {
		object := testObject(t, coff.MachineI386)
		text := testSection(t, object, ".text", 4)
		rdata := testSection(t, object, ".rdata", 4)
		testFunction(t, object, text, "_go", 0)
		target := testFunction(t, object, text, "target", 0)
		testRelocation(rdata, 0, coff.RelI386Dir32, target)
		if _, err := EmitPIC(object, PICOptions{}); err == nil || !strings.Contains(err.Error(), "suspected jump table") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("patch bounds", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		testFunction(t, object, text, "go", 0)
		target := testFunction(t, object, text, "target", 0)
		testRelocation(text, 2, coff.RelAMD64Rel32, target)
		if _, err := EmitPIC(object, PICOptions{}); err == nil || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unresolved", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		target := testUndefined(t, object, "missing", coff.SymbolTypeFunction)
		testRelocation(text, 0, coff.RelAMD64Rel32, target)
		if _, err := EmitPIC(object, PICOptions{}); err == nil || !strings.Contains(err.Error(), "unresolved") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported relocation", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		target := testFunction(t, object, text, "target", 0)
		testRelocation(text, 0, 0xffff, target)
		if _, err := EmitPIC(object, PICOptions{}); err == nil || !strings.Contains(err.Error(), "unsupported relocation") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestEmitPICOptionalDataAndBSS(t *testing.T) {
	object := testObject(t, coff.MachineI386)
	text := testSection(t, object, ".text", 1)
	rdata := testSection(t, object, ".rdata", 2)
	data := testSection(t, object, ".data", 3)
	bss := testSection(t, object, ".bss", 4)
	copy(text.Data, "T")
	copy(rdata.Data, "RR")
	copy(data.Data, "DDD")

	plain, err := EmitPIC(object, PICOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(plain.Bytes); got != "TRR" {
		t.Fatalf("default x86 PIC = %q, want TRR", got)
	}
	extended, err := EmitPIC(object, PICOptions{IncludeData: true, IncludeBSS: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(extended.Bytes), 10; got != want {
		t.Fatalf("extended PIC length = %d, want %d", got, want)
	}
	if placement, ok := extended.Layout.Placement(rdata); !ok || placement.Offset != 1 {
		t.Fatalf("rdata placement = %#v, %v", placement, ok)
	}
	if placement, ok := extended.Layout.Placement(data); !ok || placement.Offset != 3 {
		t.Fatalf("data placement = %#v, %v", placement, ok)
	}
	if placement, ok := extended.Layout.Placement(bss); !ok || placement.Offset != 6 {
		t.Fatalf("BSS placement = %#v, %v", placement, ok)
	}
}

func TestRelocationIntegerBounds(t *testing.T) {
	buffer := make([]byte, 4)
	if err := writeInt32(buffer, 0, int64(math.MaxInt32)+1); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("REL32 range error = %v", err)
	}
	if err := writeAbsolute32(buffer, 0, -1); err == nil || !strings.Contains(err.Error(), "uint32") {
		t.Fatalf("absolute range error = %v", err)
	}
}
