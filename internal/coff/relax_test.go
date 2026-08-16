// SPDX-License-Identifier: GPL-3.0-only

package coff

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestRelaxReferencePointers(t *testing.T) {
	t.Parallel()
	object, text, refptr, target := relaxFixture(t, []byte{0x48, 0x8b, 0x15, 0, 0, 0, 0, 0xc3}, 3)
	orphan := NewSection(".rdata$.refptr.orphan", make([]byte, 8))
	if err := object.AddSection(orphan); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(NewDataSymbol(orphan, ".refptr.orphan", 0)); err != nil {
		t.Fatal(err)
	}

	report, err := RelaxReferencePointers(object)
	if err != nil {
		t.Fatal(err)
	}
	if report.RelaxedRelocations != 1 {
		t.Fatalf("relaxed = %d, want 1", report.RelaxedRelocations)
	}
	if got, want := report.RemovedSections, []string{".rdata$.refptr.func", ".rdata$.refptr.orphan"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("removed sections = %#v, want %#v", got, want)
	}
	if text.Data[1] != 0x8d {
		t.Fatalf("opcode = %#x, want LEA 0x8d", text.Data[1])
	}
	relocation := text.Relocations[0]
	if relocation.SymbolName != "func" || relocation.Symbol != target {
		t.Fatalf("relocation = %#v, want target func", relocation)
	}
	if object.GetSection(refptr.Name) != nil || object.GetSymbol(".refptr.func") != nil || object.GetSection(orphan.Name) != nil {
		t.Fatal("garbage refptr sections or symbols remain")
	}
	if object.GetSymbol("func") != target {
		t.Fatal("target symbol was removed")
	}

	second, err := RelaxReferencePointers(object)
	if err != nil {
		t.Fatal(err)
	}
	if second.RelaxedRelocations != 0 || len(second.RemovedSections) != 0 {
		t.Fatalf("second relaxation = %#v, want idempotent no-op", second)
	}
}

func TestRelaxReferencePointersRetainsReferencedAndUnmatchedRefptrs(t *testing.T) {
	t.Parallel()

	t.Run("referenced elsewhere", func(t *testing.T) {
		t.Parallel()
		object, text, refptr, _ := relaxFixture(t, []byte{0x48, 0x8b, 0x15, 0, 0, 0, 0, 0xc3}, 3)
		data := NewSection(".data", make([]byte, 8))
		if err := object.AddSection(data); err != nil {
			t.Fatal(err)
		}
		refptrSymbol := object.GetSymbol(".refptr.func")
		data.Relocations = append(data.Relocations, &Relocation{Section: data, VirtualAddress: 0, SymbolName: refptrSymbol.Name, Symbol: refptrSymbol, Type: RelAMD64Addr64})
		report, err := RelaxReferencePointers(object)
		if err != nil {
			t.Fatal(err)
		}
		if report.RelaxedRelocations != 1 || object.GetSection(refptr.Name) == nil || text.Data[1] != 0x8d {
			t.Fatalf("report=%#v refptr=%#v text=%x", report, object.GetSection(refptr.Name), text.Data)
		}
	})

	t.Run("opcode does not match", func(t *testing.T) {
		t.Parallel()
		object, text, refptr, _ := relaxFixture(t, []byte{0x48, 0x89, 0x15, 0, 0, 0, 0, 0xc3}, 3)
		report, err := RelaxReferencePointers(object)
		if err != nil {
			t.Fatal(err)
		}
		if report.RelaxedRelocations != 0 || object.GetSection(refptr.Name) == nil || text.Data[1] != 0x89 {
			t.Fatalf("report=%#v refptr=%#v text=%x", report, object.GetSection(refptr.Name), text.Data)
		}
	})
}

func TestRelaxReferencePointersValidationIsTransactional(t *testing.T) {
	t.Parallel()
	object, text, _, _ := relaxFixture(t, []byte{0x48, 0x8b, 0x15, 0, 0, 0, 0, 0xc3}, 3)
	bad := NewSection(".text$bad", []byte{0x90})
	bad.Characteristics = FlagsForName(".text")
	if err := object.AddSection(bad); err != nil {
		t.Fatal(err)
	}
	refptr := object.GetSymbol(".refptr.func")
	bad.Relocations = append(bad.Relocations, &Relocation{Section: bad, VirtualAddress: 0, SymbolName: refptr.Name, Symbol: refptr, Type: RelAMD64Rel32})
	original := append([]byte(nil), text.Data...)
	_, err := RelaxReferencePointers(object)
	if err == nil || !strings.Contains(err.Error(), "outside section") {
		t.Fatalf("error = %v, want bounds error", err)
	}
	if !bytes.Equal(text.Data, original) || text.Relocations[0].SymbolName != ".refptr.func" {
		t.Fatalf("object mutated after validation failure: text=%x relocation=%q", text.Data, text.Relocations[0].SymbolName)
	}
}

func TestRelaxReferencePointersRejectsUnsupportedMachine(t *testing.T) {
	t.Parallel()
	object, err := NewObject(MachineI386)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RelaxReferencePointers(object); err == nil || !strings.Contains(err.Error(), "x64 only") {
		t.Fatalf("error = %v, want x64-only error", err)
	}
	if _, err := RelaxReferencePointers(nil); err == nil {
		t.Fatal("nil object unexpectedly accepted")
	}
}

func relaxFixture(t *testing.T, code []byte, relocationVA uint32) (*Object, *Section, *Section, *Symbol) {
	t.Helper()
	object, err := NewObject(MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	text := NewSection(".text", code)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	target := NewFunctionSymbol(text, "func", uint32(len(code)-1))
	if err := object.AddSymbol(target); err != nil {
		t.Fatal(err)
	}
	refptr := NewSection(".rdata$.refptr.func", make([]byte, 8))
	if err := object.AddSection(refptr); err != nil {
		t.Fatal(err)
	}
	refptrSymbol := NewDataSymbol(refptr, ".refptr.func", 0)
	if err := object.AddSymbol(refptrSymbol); err != nil {
		t.Fatal(err)
	}
	text.Relocations = append(text.Relocations, &Relocation{Section: text, VirtualAddress: relocationVA, SymbolName: refptrSymbol.Name, Symbol: refptrSymbol, Type: RelAMD64Rel32})
	return object, text, refptr, target
}
