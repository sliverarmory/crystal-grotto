// SPDX-License-Identifier: GPL-3.0-only

package hooks

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
)

func TestNewArchitectureDefaults(t *testing.T) {
	x64 := hookTestObject(t, coff.MachineAMD64, "wrapper")
	model, err := New(x64)
	if err != nil {
		t.Fatal(err)
	}
	if !model.IsProtected("dprintf") || model.IsProtected("_dprintf") {
		t.Fatalf("x64 protected = %#v", model.Snapshot().Protected)
	}
	if model.Machine() != coff.MachineAMD64 || model.CatchEncodingError() != nil {
		t.Fatalf("initial model machine=%s catch error=%v", model.Machine(), model.CatchEncodingError())
	}
	x86 := hookTestObject(t, coff.MachineI386, "_wrapper")
	model, err = New(x86)
	if err != nil {
		t.Fatal(err)
	}
	if !model.IsProtected("_dprintf") || model.IsProtected("dprintf") {
		t.Fatalf("x86 protected = %#v", model.Snapshot().Protected)
	}
	arm, _ := coff.NewObject(coff.MachineARM64)
	if _, err := New(arm); !errors.Is(err, ErrUnsupportedMachine) {
		t.Fatalf("ARM New error = %v", err)
	}
	if _, err := New(nil); !errors.Is(err, ErrNilObject) {
		t.Fatalf("nil New error = %v", err)
	}
}

func TestAttachChainPrecedenceAndTransactionalUpdates(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "wrap1", "wrap2", "caller", "other")
	base := mustNewModel(t, object)
	first := mustApply(t, base, object, "attach", []string{"KERNEL32$Sleep", "wrap1"}, nil)
	second := mustApply(t, first, object, "attach", []string{"KERNEL32$Sleep", "wrap2"}, nil)

	assertExternal(t, second, "caller", "KERNEL32$Sleep", "wrap1", true)
	assertExternal(t, second, "wrap1", "KERNEL32$Sleep", "wrap2", true)
	assertExternal(t, second, "wrap2", "KERNEL32$Sleep", "", false)
	assertExternal(t, second, "KERNEL32$Sleep", "KERNEL32$Sleep", "", false)
	assertExternal(t, base, "caller", "KERNEL32$Sleep", "", false)

	duplicate, err := applyCommand(context.Background(), second, object, "attach", []string{"KERNEL32$Sleep", "wrap2"}, nil)
	if err == nil || !strings.Contains(err.Error(), "already declared. Order matters") || duplicate != nil {
		t.Fatalf("duplicate result = %#v, %v", duplicate, err)
	}
	if got := second.Snapshot().External[0].Hooks; len(got) != 2 {
		t.Fatalf("failed update mutated receiver: %#v", got)
	}
	if _, err := applyCommand(context.Background(), second, object, "attach", []string{"not-a-module", "wrap1"}, nil); err == nil || !strings.Contains(err.Error(), "MODULE$Function") {
		t.Fatalf("bad target error = %v", err)
	}

	optOutFirst := mustApply(t, second, object, "optout", []string{"caller", "wrap1"}, nil)
	assertExternal(t, optOutFirst, "caller", "KERNEL32$Sleep", "wrap2", true)
	optOutLater := mustApply(t, second, object, "optout", []string{"caller", "wrap2"}, nil)
	assertExternal(t, optOutLater, "caller", "KERNEL32$Sleep", "", false)

	preserved := mustApply(t, second, object, "preserve", []string{"KERNEL32$Sleep", "caller"}, nil)
	assertExternal(t, preserved, "caller", "KERNEL32$Sleep", "", false)
	protected := mustApply(t, second, object, "protect", []string{"caller,unknown"}, nil)
	assertExternal(t, protected, "caller", "KERNEL32$Sleep", "", false)
	if !protected.IsProtected("unknown") {
		t.Fatal("protect unexpectedly validated/ignored unknown symbol")
	}

	plan := second.PlanAttach("caller", "KERNEL32$Sleep")
	if !plan.Matched || plan.Wrapper != "wrap1" || !plan.RequiresEncoder || !errors.Is(plan.EncodingError(), ErrEncoderRequired) {
		t.Fatalf("attach plan = %#v, %v", plan, plan.EncodingError())
	}
	if err := second.PlanAttach("caller", "OTHER$Missing").EncodingError(); err != nil {
		t.Fatalf("unmatched plan encoding error = %v", err)
	}
	importPlan := second.PlanAttachImport("caller", "__imp_KERNEL32$Sleep")
	if !importPlan.Matched || importPlan.Wrapper != "wrap1" {
		t.Fatalf("import attach plan = %#v", importPlan)
	}
	if plan := second.PlanAttachImport("caller", "ordinary_symbol"); plan.Matched || plan.Target != "" {
		t.Fatalf("non-import attach plan = %#v", plan)
	}
}

func TestPlanAttachImportSpecialAndNakedTargets(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "kernel", "naked", "caller")
	model := mustNewModel(t, object)
	model = mustApply(t, model, object, "attach", []string{"KERNEL32$LoadLibraryA", "kernel"}, nil)
	model = mustApply(t, model, object, "attach", []string{"$Custom", "naked"}, nil)
	if plan := model.PlanAttachImport("caller", "__imp_LoadLibraryA"); !plan.Matched || plan.Target != "KERNEL32$LoadLibraryA" || plan.Wrapper != "kernel" {
		t.Fatalf("special naked import plan = %#v", plan)
	}
	if plan := model.PlanAttachImport("caller", "__imp_Custom"); !plan.Matched || plan.Target != "$Custom" || plan.Wrapper != "naked" {
		t.Fatalf("ordinary naked import plan = %#v", plan)
	}
}

func TestRedirectAndSharedPreserveProtection(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "local1", "local2", "caller")
	model := mustNewModel(t, object)
	model = mustApply(t, model, object, "redirect", []string{"target", "local1"}, nil)
	model = mustApply(t, model, object, "redirect", []string{"target", "local2"}, nil)
	assertLocal(t, model, "caller", "target", "local1", true)
	assertLocal(t, model, "local1", "target", "local2", true)
	if model.HasExternalHooks() || !model.HasLocalHooks() {
		t.Fatalf("hook flags external=%v local=%v", model.HasExternalHooks(), model.HasLocalHooks())
	}
	model = mustApply(t, model, object, "preserve", []string{"target", "caller"}, nil)
	assertLocal(t, model, "caller", "target", "", false)
	plan := model.PlanRedirect("local1", "target")
	if !plan.Matched || plan.Wrapper != "local2" || !errors.Is(plan.EncodingError(), ErrEncoderRequired) {
		t.Fatalf("redirect plan = %#v", plan)
	}
}

func TestPreserveAndOptOutValidateAtomically(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "valid", "wrapper")
	model := mustNewModel(t, object)
	if _, err := applyCommand(context.Background(), model, object, "preserve", []string{"target", "valid,missing"}, nil); err == nil {
		t.Fatal("preserve with missing symbol succeeded")
	}
	if model.IsPreserved("target", "valid") {
		t.Fatal("failed preserve partially mutated model")
	}
	if _, err := applyCommand(context.Background(), model, object, "optout", []string{"valid", "wrapper,missing"}, nil); err == nil {
		t.Fatal("optout with missing wrapper succeeded")
	}
	if model.IsOptOut("valid", "wrapper") {
		t.Fatal("failed optout partially mutated model")
	}
}

func TestAddHookOverrideResolutionAndFiltering(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "wrapper", "other")
	model := mustNewModel(t, object)
	model = mustApply(t, model, object, "attach", []string{"KERNEL32$Sleep", "wrapper"}, nil)
	model = mustApply(t, model, object, "addhook", []string{"kernel32$Sleep"}, nil)
	model = mustApply(t, model, object, "addhook", []string{"USER32$MessageBoxA", "other"}, nil)
	hooks := model.ResolveHooks()
	if len(hooks) != 2 || hooks[0].Target != "KERNEL32$Sleep" || !hooks[0].Self || hooks[1].Wrapper != "other" {
		t.Fatalf("resolve hooks = %#v", hooks)
	}
	if hooks[0].FunctionHash() != 0xdb2d49b0 {
		t.Fatalf("Sleep hash = %#08x", hooks[0].FunctionHash())
	}
	got, found := model.ResolveRegisteredHook("caller", hooks[0])
	assertResolution(t, got, found, "wrapper", true)
	got, found = model.ResolveRegisteredHook("caller", hooks[1])
	assertResolution(t, got, found, "other", true)

	// The resolve map is keyed only by function. A later module declaration
	// replaces the earlier entry without adding a second key.
	overridden := mustApply(t, model, object, "addhook", []string{"NTDLL$Sleep", "other"}, nil)
	if got := overridden.ResolveHooks(); len(got) != 2 || got[0].Target != "NTDLL$Sleep" {
		t.Fatalf("overridden resolve hooks = %#v", got)
	}

	content := importedCOFF(t, coff.MachineAMD64, "__imp_KERNEL32$Sleep")
	filtered := mustApply(t, model, object, "filterhooks", []string{"$OBJECT"}, func(reference string) ([]byte, error) {
		if reference != "$OBJECT" {
			t.Fatalf("resolver reference = %q", reference)
		}
		return content, nil
	})
	if got := filtered.ResolveHooks(); len(got) != 1 || got[0].Target != "KERNEL32$Sleep" {
		t.Fatalf("filtered hooks = %#v", got)
	}
	if len(model.ResolveHooks()) != 2 {
		t.Fatal("filter mutated receiver")
	}

	before := model.Snapshot()
	if _, err := applyCommand(context.Background(), model, object, "filterhooks", []string{"$BAD"}, func(string) ([]byte, error) {
		return []byte{1, 2, 3}, nil
	}); err == nil || err.Error() != "Argument is not a COFF or DLL." {
		t.Fatalf("bad filter error = %v", err)
	}
	if !reflect.DeepEqual(model.Snapshot(), before) {
		t.Fatal("failed filter mutated receiver")
	}
}

func TestSnapshotDefensiveAndStable(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "wrapper", "caller", "handler")
	model := mustNewModel(t, object)
	model = mustApply(t, model, object, "attach", []string{"KERNEL32$Sleep", "wrapper"}, nil)
	model = mustApply(t, model, object, "preserve", []string{"KERNEL32$Sleep", "caller"}, nil)
	model = mustApply(t, model, object, "catch", []string{"caller", "handler"}, nil)
	content := []byte{1, 2, 3}
	model = mustApply(t, model, object, "intrinsic", []string{"__custom", "$CODE"}, func(string) ([]byte, error) {
		return content, nil
	})
	content[0] = 0xff

	first := model.Snapshot()
	second := model.Snapshot()
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("snapshots differ:\n%#v\n%#v", first, second)
	}
	if !bytes.Equal(first.Intrinsics[0].Content, []byte{1, 2, 3}) {
		t.Fatalf("intrinsic storage aliased input: %x", first.Intrinsics[0].Content)
	}
	first.External[0].Hooks[0].Wrapper = "changed"
	first.Preserved[0].Values[0] = "changed"
	first.Protected[0] = "changed"
	first.Intrinsics[0].Content[0] = 9
	first.Catches[0].Handler = "changed"
	if !reflect.DeepEqual(model.Snapshot(), second) {
		t.Fatal("snapshot exposed model storage")
	}
}

func TestApplyContextObjectAndResolverErrors(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "wrapper")
	model := mustNewModel(t, object)
	directive, _ := Parse("protect", []string{"wrapper"})
	if _, err := model.Apply(nil, object, directive, nil); !errors.Is(err, ErrNilContext) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := (*Model)(nil).Apply(context.Background(), object, directive, nil); !errors.Is(err, ErrNilModel) {
		t.Fatalf("nil model error = %v", err)
	}
	if _, err := model.Apply(context.Background(), nil, directive, nil); !errors.Is(err, ErrNilObject) {
		t.Fatalf("nil object error = %v", err)
	}
	x86 := hookTestObject(t, coff.MachineI386, "_wrapper")
	if _, err := model.Apply(context.Background(), x86, directive, nil); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("machine mismatch error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := model.Apply(canceled, object, directive, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
	intrinsic, _ := Parse("intrinsic", []string{"__custom", "$CODE"})
	if _, err := model.Apply(context.Background(), object, intrinsic, nil); err == nil || !strings.Contains(err.Error(), "requires a byte resolver") {
		t.Fatalf("nil resolver error = %v", err)
	}
	sentinel := errors.New("resolve failed")
	if _, err := model.Apply(context.Background(), object, intrinsic, func(string) ([]byte, error) { return nil, sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("resolver error = %v", err)
	}
}

func TestConcurrentQueriesAndTransactionalApply(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "wrapper", "caller")
	base := mustNewModel(t, object)
	base = mustApply(t, base, object, "attach", []string{"KERNEL32$Sleep", "wrapper"}, nil)
	const workers = 32
	var group sync.WaitGroup
	errorsFound := make(chan error, workers)
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if wrapper, found := base.ResolveExternal("caller", "KERNEL32$Sleep"); !found || wrapper != "wrapper" {
				errorsFound <- errors.New("unexpected resolution")
				return
			}
			derived, err := applyCommand(context.Background(), base, object, "protect", []string{"caller"}, nil)
			if err != nil {
				errorsFound <- err
				return
			}
			if _, found := derived.ResolveExternal("caller", "KERNEL32$Sleep"); found {
				errorsFound <- errors.New("derived protection did not apply")
			}
		}()
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	assertExternal(t, base, "caller", "KERNEL32$Sleep", "wrapper", true)
}

func hookTestObject(t *testing.T, machine coff.Machine, functions ...string) *coff.Object {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", make([]byte, len(functions)+1))
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	for index, function := range functions {
		if err := object.AddSymbol(coff.NewFunctionSymbol(text, function, uint32(index))); err != nil {
			t.Fatal(err)
		}
	}
	return object
}

func importedCOFF(t *testing.T, machine coff.Machine, importSymbol string) []byte {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", make([]byte, 4))
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	undefined := &coff.Symbol{Name: importSymbol, StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(undefined); err != nil {
		t.Fatal(err)
	}
	relocType := coff.RelAMD64Rel32
	if machine == coff.MachineI386 {
		relocType = coff.RelI386Rel32
	}
	text.Relocations = []*coff.Relocation{{
		Section: text, VirtualAddress: 0, Symbol: undefined, SymbolName: undefined.Name, Type: relocType,
	}}
	content, err := coffwrite.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func mustNewModel(t *testing.T, object *coff.Object) *Model {
	t.Helper()
	model, err := New(object)
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func mustApply(t *testing.T, model *Model, object *coff.Object, command string, arguments []string, resolver ByteResolver) *Model {
	t.Helper()
	result, err := applyCommand(context.Background(), model, object, command, arguments, resolver)
	if err != nil {
		t.Fatalf("%s %#v: %v", command, arguments, err)
	}
	return result
}

func applyCommand(ctx context.Context, model *Model, object *coff.Object, command string, arguments []string, resolver ByteResolver) (*Model, error) {
	directive, err := Parse(command, arguments)
	if err != nil {
		return nil, err
	}
	return model.Apply(ctx, object, directive, resolver)
}

func assertResolution(t *testing.T, got string, found bool, want string, wantFound bool) {
	t.Helper()
	if got != want || found != wantFound {
		t.Fatalf("resolution = %q,%v, want %q,%v", got, found, want, wantFound)
	}
}

func assertExternal(t *testing.T, model *Model, context, target, want string, wantFound bool) {
	t.Helper()
	got, found := model.ResolveExternal(context, target)
	assertResolution(t, got, found, want, wantFound)
}

func assertLocal(t *testing.T, model *Model, context, target, want string, wantFound bool) {
	t.Helper()
	got, found := model.ResolveLocal(context, target)
	assertResolution(t, got, found, want, wantFound)
}
