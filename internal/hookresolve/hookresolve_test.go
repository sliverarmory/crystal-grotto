// SPDX-License-Identifier: GPL-3.0-only

package hookresolve

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
	"github.com/sliverarmory/crystal-grotto/internal/linker"
)

func TestApplyExactStubVectorsAndLinkerIntegration(t *testing.T) {
	tests := []struct {
		name             string
		machine          coff.Machine
		intrinsic        string
		relocationType   uint16
		wantStub         []byte
		wantWrapperReloc uint16
		wantRelocOffset  uint32
		wantHashOffset   int
	}{
		{
			name: "x64", machine: coff.MachineAMD64, intrinsic: "__resolve_hook",
			relocationType: coff.RelAMD64Rel32, wantWrapperReloc: coff.RelAMD64Rel32, wantRelocOffset: 21, wantHashOffset: 6,
			wantStub: []byte{
				0xe9, 0x1d, 0, 0, 0,
				0xba, 0, 0, 0, 0, 0x39, 0xd1, 0x0f, 0x85, 0x0c, 0, 0, 0,
				0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xe9, 0x03, 0, 0, 0,
				0x48, 0x31, 0xc0, 0xc3,
			},
		},
		{
			name: "x86", machine: coff.MachineI386, intrinsic: "___resolve_hook",
			relocationType: coff.RelI386Rel32, wantWrapperReloc: coff.RelI386Dir32, wantRelocOffset: 23, wantHashOffset: 10,
			wantStub: []byte{
				0xe9, 0x1e, 0, 0, 0,
				0x8b, 0x4c, 0x24, 0x04,
				0xba, 0, 0, 0, 0, 0x39, 0xd1, 0x0f, 0x85, 0x0a, 0, 0, 0,
				0xb8, 0, 0, 0, 0, 0xe9, 0x02, 0, 0, 0,
				0x31, 0xc0, 0xc3,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := testObject(t, test.machine, []byte{0xe8, 0, 0, 0, 0, 0xc3, 0xb8, 0x2a, 0, 0, 0, 0xc3})
			text := object.GetSection(".text")
			addFunction(t, object, text, entryName(test.machine), 0)
			addFunction(t, object, text, "wrapper", 6)
			intrinsic := &coff.Symbol{Name: test.intrinsic, Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
			if err := object.AddSymbol(intrinsic); err != nil {
				t.Fatal(err)
			}
			text.Relocations = []*coff.Relocation{{
				Section: text, VirtualAddress: 1, SymbolName: intrinsic.Name,
				Symbol: intrinsic, Type: test.relocationType,
			}}
			model := addHookModel(t, object, "KERNEL32$Sleep", "wrapper")
			before := append([]byte(nil), text.Data...)
			result, report, err := Apply(context.Background(), object, model, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if report.RewrittenSites != 1 || report.ResolverEntries != 1 || report.RandomDraws != 0 || report.StubSection == "" {
				t.Fatalf("report = %#v", report)
			}
			if !bytes.Equal(text.Data, before) || text.Relocations[0].SymbolName != test.intrinsic {
				t.Fatal("Apply mutated its source object")
			}
			stub := result.GetSection(report.StubSection)
			if stub == nil {
				t.Fatalf("missing stub section %q", report.StubSection)
			}
			want := append([]byte(nil), test.wantStub...)
			binary.LittleEndian.PutUint32(want[test.wantHashOffset:test.wantHashOffset+4], model.ResolveHooks()[0].FunctionHash())
			if !bytes.Equal(stub.Data, want) {
				t.Fatalf("stub = %x\nwant = %x", stub.Data, want)
			}
			if len(stub.Relocations) != 1 || stub.Relocations[0].VirtualAddress != test.wantRelocOffset || stub.Relocations[0].SymbolName != "wrapper" || stub.Relocations[0].Type != test.wantWrapperReloc {
				t.Fatalf("stub relocations = %#v", stub.Relocations)
			}
			if got := result.GetSection(".text").Relocations[0]; got.SymbolName == test.intrinsic || got.Symbol == nil || got.Symbol.Name != got.SymbolName {
				t.Fatalf("rewritten call relocation = %#v", got)
			}
			merged, err := linker.Merge(result)
			if err != nil {
				t.Fatal(err)
			}
			if test.machine == coff.MachineAMD64 {
				if _, err := linker.EmitPIC(merged, linker.PICOptions{EntrySymbol: entryName(test.machine)}); err != nil {
					t.Fatalf("EmitPIC after hook resolver: %v", err)
				}
			}
		})
	}
}

func TestApplySelfSelectionAndJavaShuffle(t *testing.T) {
	object := testObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3, 0xc3, 0xc3})
	text := object.GetSection(".text")
	addFunction(t, object, text, "go", 0)
	addFunction(t, object, text, "first", 6)
	addFunction(t, object, text, "second", 7)
	intrinsic := &coff.Symbol{Name: "__resolve_hook", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(intrinsic); err != nil {
		t.Fatal(err)
	}
	text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 1, SymbolName: intrinsic.Name, Symbol: intrinsic, Type: coff.RelAMD64Rel32}}
	model, err := hooks.New(object)
	if err != nil {
		t.Fatal(err)
	}
	for _, directive := range []struct {
		name string
		args []string
	}{
		{name: "attach", args: []string{"KERNEL32$Sleep", "first"}},
		{name: "addhook", args: []string{"KERNEL32$Sleep"}},
		{name: "addhook", args: []string{"NTDLL$Wait", "second"}},
	} {
		parsed, err := hooks.Parse(directive.name, directive.args)
		if err != nil {
			t.Fatal(err)
		}
		model, err = model.Apply(context.Background(), object, parsed, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	seed := int64(123)
	result, report, err := Apply(context.Background(), object, model, Options{Seed: &seed})
	if err != nil {
		t.Fatal(err)
	}
	if report.ResolverEntries != 2 || report.RandomDraws != 1 {
		t.Fatalf("report = %#v", report)
	}
	stub := result.GetSection(report.StubSection)
	if stub == nil || len(stub.Relocations) != 2 {
		t.Fatalf("stub = %#v", stub)
	}
	// Java seed 123 swaps a two-entry slice. Both the explicit and self-selected
	// wrapper must remain present in that shuffled order.
	if stub.Relocations[0].SymbolName != "first" || stub.Relocations[1].SymbolName != "second" {
		t.Fatalf("wrapper order = %q, %q", stub.Relocations[0].SymbolName, stub.Relocations[1].SymbolName)
	}
}

func TestApplyRejectsUnsupportedTransactionally(t *testing.T) {
	object := testObject(t, coff.MachineAMD64, []byte{0xff, 0xd0, 0xc3})
	text := object.GetSection(".text")
	addFunction(t, object, text, "go", 0)
	intrinsic := &coff.Symbol{Name: "__resolve_hook", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(intrinsic); err != nil {
		t.Fatal(err)
	}
	text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 1, SymbolName: intrinsic.Name, Symbol: intrinsic, Type: coff.RelAMD64Rel32}}
	model, _ := hooks.New(object)
	before := append([]byte(nil), text.Data...)
	_, _, err := Apply(context.Background(), object, model, Options{})
	if err == nil || !errors.Is(err, ErrUnsupportedForm) {
		t.Fatalf("error = %v", err)
	}
	if !bytes.Equal(text.Data, before) || text.Relocations[0].SymbolName != intrinsic.Name || len(object.Sections) != 1 {
		t.Fatal("failed Apply mutated input")
	}
}

func TestApplyRandomFailureAndNoSitesAreTransactional(t *testing.T) {
	object := testObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3, 0xc3, 0xc3})
	text := object.GetSection(".text")
	addFunction(t, object, text, "go", 0)
	addFunction(t, object, text, "first", 6)
	addFunction(t, object, text, "second", 7)
	intrinsic := &coff.Symbol{Name: "__resolve_hook", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(intrinsic); err != nil {
		t.Fatal(err)
	}
	text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 1, SymbolName: intrinsic.Name, Symbol: intrinsic, Type: coff.RelAMD64Rel32}}
	model := addHookModel(t, object, "KERNEL32$Sleep", "first")
	parsed, _ := hooks.Parse("addhook", []string{"NTDLL$Wait", "second"})
	model, _ = model.Apply(context.Background(), object, parsed, nil)
	_, _, err := Apply(context.Background(), object, model, Options{Random: bytes.NewReader(nil)})
	if err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("random error = %v", err)
	}
	if text.Relocations[0].SymbolName != intrinsic.Name || len(object.Sections) != 1 {
		t.Fatal("random failure mutated input")
	}

	plain := testObject(t, coff.MachineAMD64, []byte{0xc3})
	addFunction(t, plain, plain.GetSection(".text"), "go", 0)
	plainModel, _ := hooks.New(plain)
	clone, report, err := Apply(context.Background(), plain, plainModel, Options{})
	if err != nil || report.RewrittenSites != 0 || clone == plain || clone.GetSection(".text") == plain.GetSection(".text") {
		t.Fatalf("no-site result = %#v, %#v, %v", clone, report, err)
	}
}

func TestApplyConcurrentDeterminism(t *testing.T) {
	object := testObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3, 0xc3})
	text := object.GetSection(".text")
	addFunction(t, object, text, "go", 0)
	addFunction(t, object, text, "wrapper", 6)
	intrinsic := &coff.Symbol{Name: "__resolve_hook", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
	_ = object.AddSymbol(intrinsic)
	text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 1, SymbolName: intrinsic.Name, Symbol: intrinsic, Type: coff.RelAMD64Rel32}}
	model := addHookModel(t, object, "KERNEL32$Sleep", "wrapper")
	const workers = 8
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			seed := int64(123)
			result, report, err := Apply(context.Background(), object, model, Options{Seed: &seed})
			if err != nil {
				errorsChannel <- err
				return
			}
			if result.GetSection(report.StubSection) == nil || report.RewrittenSites != 1 {
				errorsChannel <- errors.New("invalid concurrent result")
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func testObject(t *testing.T, machine coff.Machine, code []byte) *coff.Object {
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

func addHookModel(t *testing.T, object *coff.Object, target, wrapper string) *hooks.Model {
	t.Helper()
	model, err := hooks.New(object)
	if err != nil {
		t.Fatal(err)
	}
	directive, err := hooks.Parse("addhook", []string{target, wrapper})
	if err != nil {
		t.Fatal(err)
	}
	model, err = model.Apply(context.Background(), object, directive, nil)
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func entryName(machine coff.Machine) string {
	if machine == coff.MachineI386 {
		return "_go"
	}
	return "go"
}
