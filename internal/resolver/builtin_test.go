// SPDX-License-Identifier: GPL-3.0-only

package resolver

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
	"github.com/sliverarmory/crystal-grotto/internal/linker"
)

func TestApplyBuiltinExactX64HashCall(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineAMD64, []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3})
	text := object.GetSection(".text")
	addFunction(t, object, text, "resolve", 6)
	addImportRelocation(t, object, "__imp_KERNEL32$Sleep", 2, coff.RelAMD64Rel32)

	result, plan, err := ApplyBuiltin(object, defaultConfiguration(t, object, "resolve", MethodROR13))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Sites) != 1 || plan.Sites[0].StubSymbol != "__cpl_dfr_00000000" {
		t.Fatalf("plan = %#v", plan)
	}
	wantText := mustHex(t, "90e800000000c3")
	if got := result.GetSection(".text").Data; !bytes.Equal(got, wantText) {
		t.Fatalf("rewritten text bytes:\n got %x\nwant %x", got, wantText)
	}
	wantStub := mustHex(t, "e937000000"+
		"9c51524150415141524153554889e54883e4f04883ec20"+
		"b95bbc4a6abab0492ddbe8000000004889ec5d415b415a415941585a599dffe0")
	if got := result.GetSection(".text$cpl_dfr").Data; !bytes.Equal(got, wantStub) {
		t.Fatalf("resolver stub bytes:\n got %x\nwant %x", got, wantStub)
	}
	assertBuiltinRelocations(t, result, plan.Sites[0], 34)
	if got := object.GetSection(".text").Data; !bytes.Equal(got, []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3}) {
		t.Fatalf("input mutated: %x", got)
	}
}

func TestApplyBuiltinExactX86StringMove(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineI386, []byte{0x8b, 0x0d, 0, 0, 0, 0, 0xc3})
	text := object.GetSection(".text")
	addFunction(t, object, text, "_resolve", 6)
	addImportRelocation(t, object, "__imp__KERNEL32$Sleep@4", 2, coff.RelI386Dir32)

	result, plan, err := ApplyBuiltin(object, defaultConfiguration(t, object, "_resolve", MethodStrings))
	if err != nil {
		t.Fatal(err)
	}
	wantText := mustHex(t, "90e800000000c3")
	if got := result.GetSection(".text").Data; !bytes.Equal(got, wantText) {
		t.Fatalf("rewritten text bytes:\n got %x\nwant %x", got, wantText)
	}
	wantStub := mustHex(t, "e937000000"+
		"9c5051526800000000680000000068454c3332684b45524e89e1"+
		"687000000068536c656589e25251e80000000083c4205a5989c1589dc3")
	if got := result.GetSection(".text$cpl_dfr").Data; !bytes.Equal(got, wantStub) {
		t.Fatalf("resolver stub bytes:\n got %x\nwant %x", got, wantStub)
	}
	assertBuiltinRelocations(t, result, plan.Sites[0], 41)
	linked, err := linker.Merge(result)
	if err != nil {
		t.Fatal(err)
	}
	linkedText := linked.GetSection(".text")
	if len(linkedText.Relocations) != 0 {
		t.Fatalf("x86 local relocations remain after merge: %#v", linkedText.Relocations)
	}
	stub := linked.GetSymbol(plan.Sites[0].StubSymbol)
	if got, want := int32(binary.LittleEndian.Uint32(linkedText.Data[2:6])), int32(stub.Value)-6; got != want {
		t.Fatalf("x86 site displacement = %d, want %d", got, want)
	}
}

func TestApplyBuiltinCoversEveryPlannedForm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		machine        coff.Machine
		code           []byte
		offset         uint32
		relocationType uint16
		form           Form
		destination    string
		prefix         []byte
		stubTail       []byte
	}{
		{name: "x64 call", machine: coff.MachineAMD64, code: []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelAMD64Rel32, form: FormCall64, destination: "rax", prefix: []byte{0x90, 0xe8}, stubTail: []byte{0x9d, 0xff, 0xe0}},
		{name: "x64 jump", machine: coff.MachineAMD64, code: []byte{0xff, 0x25, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelAMD64Rel32, form: FormJump64, destination: "rax", prefix: []byte{0x90, 0xe9}, stubTail: []byte{0x9d, 0xff, 0xe0}},
		{name: "x64 move rax", machine: coff.MachineAMD64, code: []byte{0x48, 0x8b, 0x05, 0, 0, 0, 0, 0xc3}, offset: 3, relocationType: coff.RelAMD64Rel32, form: FormMove64, destination: "rax", prefix: []byte{0x90, 0x90, 0xe8}, stubTail: []byte{0x9d, 0xc3}},
		{name: "x64 move r10", machine: coff.MachineAMD64, code: []byte{0x4c, 0x8b, 0x15, 0, 0, 0, 0, 0xc3}, offset: 3, relocationType: coff.RelAMD64Rel32, form: FormMove64, destination: "r10", prefix: []byte{0x90, 0x90, 0xe8}, stubTail: []byte{0x9d, 0xc3}},
		{name: "x86 call", machine: coff.MachineI386, code: []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelI386Dir32, form: FormCall32, destination: "eax", prefix: []byte{0x90, 0xe8}, stubTail: []byte{0x9d, 0xff, 0xe0}},
		{name: "x86 jump", machine: coff.MachineI386, code: []byte{0xff, 0x25, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelI386Dir32, form: FormJump32, destination: "eax", prefix: []byte{0x90, 0xe9}, stubTail: []byte{0x9d, 0xff, 0xe0}},
		{name: "x86 move eax", machine: coff.MachineI386, code: []byte{0xa1, 0, 0, 0, 0, 0xc3}, offset: 1, relocationType: coff.RelI386Dir32, form: FormMoveEAX, destination: "eax", prefix: []byte{0xe8}, stubTail: []byte{0x9d, 0xc3}},
		{name: "x86 move ecx", machine: coff.MachineI386, code: []byte{0x8b, 0x0d, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelI386Dir32, form: FormMove32, destination: "ecx", prefix: []byte{0x90, 0xe8}, stubTail: []byte{0x9d, 0xc3}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			original := append([]byte(nil), test.code...)
			object := resolverTestObject(t, test.machine, test.code)
			text := object.GetSection(".text")
			resolverName := "resolve"
			if test.machine == coff.MachineI386 {
				resolverName = "_resolve"
			}
			addFunction(t, object, text, resolverName, uint32(len(test.code)-1))
			addImportRelocation(t, object, "__imp_KERNEL32$Sleep", test.offset, test.relocationType)

			result, plan, err := ApplyBuiltin(object, defaultConfiguration(t, object, resolverName, MethodDJB2))
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Sites) != 1 || plan.Sites[0].Form != test.form || plan.Sites[0].Destination != test.destination {
				t.Fatalf("plan = %#v", plan)
			}
			gotText := result.GetSection(".text")
			if !bytes.Equal(gotText.Data[:len(test.prefix)], test.prefix) {
				t.Fatalf("site prefix = %x, want %x", gotText.Data[:len(test.prefix)], test.prefix)
			}
			for index := int(test.offset); index < int(test.offset)+4; index++ {
				if gotText.Data[index] != 0 {
					t.Fatalf("site displacement byte %d = %#x", index, gotText.Data[index])
				}
			}
			stub := result.GetSymbol(plan.Sites[0].StubSymbol)
			if stub == nil || len(gotText.Relocations) != 1 || len(stub.Section.Relocations) != 1 {
				t.Fatalf("stub/site relocations/stub relocations = %#v / %#v / %#v", stub, gotText.Relocations, stub.Section.Relocations)
			}
			stubBytes := stub.Section.Data[stub.Value:]
			if !bytes.HasSuffix(stubBytes, test.stubTail) {
				t.Fatalf("stub tail = %x, want suffix %x", stubBytes, test.stubTail)
			}
			if stub.Section.Data[0] != 0xe9 || binary.LittleEndian.Uint32(stub.Section.Data[1:5]) != uint32(len(stub.Section.Data)-5) {
				t.Fatalf("fallthrough guard = %x", stub.Section.Data[:5])
			}
			if !bytes.Equal(object.GetSection(".text").Data, original) {
				t.Fatalf("input mutated: %x", object.GetSection(".text").Data)
			}
		})
	}
}

func TestApplyBuiltinPreservesOffsetsAndResolvesLocalRelocations(t *testing.T) {
	t.Parallel()
	code := []byte{
		0xeb, 0x06, // short branch remains byte-for-byte and still lands at offset 8
		0xff, 0x15, 0, 0, 0, 0,
		0x90,
		0xe8, 0, 0, 0, 0,
		0xc3,
	}
	object := resolverTestObject(t, coff.MachineAMD64, code)
	text := object.GetSection(".text")
	goSymbol := addFunction(t, object, text, "go", 0)
	resolveSymbol := addFunction(t, object, text, "resolve", 14)
	addImportRelocation(t, object, "__imp_KERNEL32$Sleep", 4, coff.RelAMD64Rel32)
	text.Relocations = append(text.Relocations, &coff.Relocation{
		Section: text, VirtualAddress: 10, SymbolName: resolveSymbol.Name, Symbol: resolveSymbol, Type: coff.RelAMD64Rel32,
	})

	result, plan, err := ApplyBuiltin(object, defaultConfiguration(t, object, "resolve", MethodFNV1A))
	if err != nil {
		t.Fatal(err)
	}
	resultText := result.GetSection(".text")
	if !bytes.Equal(resultText.Data[:2], code[:2]) || result.GetSymbol(goSymbol.Name).Value != 0 || result.GetSymbol(resolveSymbol.Name).Value != 14 {
		t.Fatalf("local offsets changed: data=%x go=%d resolve=%d", resultText.Data[:2], result.GetSymbol(goSymbol.Name).Value, result.GetSymbol(resolveSymbol.Name).Value)
	}
	if got := resultText.Relocations[1]; got.VirtualAddress != 10 || got.SymbolName != "resolve" || got.Type != coff.RelAMD64Rel32 {
		t.Fatalf("unrelated relocation changed: %#v", got)
	}

	raw, err := coffwrite.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := coff.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTrip.GetSection(".text").Data, resultText.Data) || roundTrip.GetSymbol(plan.Sites[0].StubSymbol) == nil || roundTrip.GetSection(".text$cpl_dfr") == nil {
		t.Fatal("COFF round trip lost rewritten bytes or stub symbol")
	}
	linked, err := linker.Merge(roundTrip)
	if err != nil {
		t.Fatal(err)
	}
	linkedText := linked.GetSection(".text")
	if len(linkedText.Relocations) != 0 {
		t.Fatalf("same-section relocations remain: %#v", linkedText.Relocations)
	}
	stub := linked.GetSymbol(plan.Sites[0].StubSymbol)
	if got, want := int32(binary.LittleEndian.Uint32(linkedText.Data[4:8])), int32(stub.Value)-8; got != want {
		t.Fatalf("site displacement = %d, want %d", got, want)
	}
	if got := int32(binary.LittleEndian.Uint32(linkedText.Data[10:14])); got != 0 {
		t.Fatalf("unrelated call displacement = %d, want 0", got)
	}
}

func TestBuiltinBackendRejectsChangedPlansBeforeMutation(t *testing.T) {
	t.Parallel()
	newFixture := func(t *testing.T) (*coff.Object, RewritePlan) {
		t.Helper()
		object := resolverTestObject(t, coff.MachineAMD64, []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3})
		addFunction(t, object, object.GetSection(".text"), "resolve", 6)
		addImportRelocation(t, object, "__imp_KERNEL32$Sleep", 2, coff.RelAMD64Rel32)
		plan, err := BuildPlan(object, defaultConfiguration(t, object, "resolve", MethodSDBM))
		if err != nil {
			t.Fatal(err)
		}
		return object, plan
	}
	tests := []struct {
		name   string
		mutate func(*coff.Object, *RewritePlan)
	}{
		{name: "machine form mismatch", mutate: func(_ *coff.Object, plan *RewritePlan) { plan.Sites[0].Form = FormCall32 }},
		{name: "source bytes changed", mutate: func(object *coff.Object, _ *RewritePlan) { object.GetSection(".text").Data[0] = 0xe8 }},
		{name: "duplicate stub symbol", mutate: func(object *coff.Object, plan *RewritePlan) {
			_ = object.AddSymbol(&coff.Symbol{Name: plan.Sites[0].StubSymbol, StorageClass: coff.SymbolClassExternal})
		}},
		{name: "missing helper", mutate: func(object *coff.Object, plan *RewritePlan) { plan.Sites[0].Resolver.Function = "missing" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			object, plan := newFixture(t)
			test.mutate(object, &plan)
			before := append([]byte(nil), object.GetSection(".text").Data...)
			err := (BuiltinBackend{}).RewriteResolvers(object, plan)
			var backendError *BackendError
			if !errors.Is(err, ErrInvalidRewritePlan) || !errors.As(err, &backendError) {
				t.Fatalf("error = %T %v", err, err)
			}
			if !bytes.Equal(object.GetSection(".text").Data, before) || len(object.GetSection(".text").Relocations) != 1 {
				t.Fatal("rejected plan partially rewrote object")
			}
		})
	}
}

func TestBuildPlanRejectsStackPointerMovesAndReservesStubNames(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name           string
		machine        coff.Machine
		code           []byte
		offset         uint32
		relocationType uint16
	}{
		{name: "x64 rsp", machine: coff.MachineAMD64, code: []byte{0x48, 0x8b, 0x25, 0, 0, 0, 0}, offset: 3, relocationType: coff.RelAMD64Rel32},
		{name: "x86 esp", machine: coff.MachineI386, code: []byte{0x8b, 0x25, 0, 0, 0, 0}, offset: 2, relocationType: coff.RelI386Dir32},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			object := resolverTestObject(t, test.machine, test.code)
			addFunction(t, object, object.GetSection(".text"), "resolve", 0)
			addImportRelocation(t, object, "__imp_KERNEL32$Sleep", test.offset, test.relocationType)
			_, err := BuildPlan(object, defaultConfiguration(t, object, "resolve", MethodROR13))
			if !errors.Is(err, ErrUnsupportedForm) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	object := resolverTestObject(t, coff.MachineAMD64, []byte{0xff, 0x15, 0, 0, 0, 0})
	addFunction(t, object, object.GetSection(".text"), "resolve", 0)
	if err := object.AddSymbol(&coff.Symbol{Name: "__cpl_dfr_00000000", StorageClass: coff.SymbolClassExternal}); err != nil {
		t.Fatal(err)
	}
	addImportRelocation(t, object, "__imp_KERNEL32$Sleep", 2, coff.RelAMD64Rel32)
	plan, err := BuildPlan(object, defaultConfiguration(t, object, "resolve", MethodROR13))
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Sites[0].StubSymbol; got != "__cpl_dfr_00000000_1" {
		t.Fatalf("stub symbol = %q", got)
	}
}

func TestBuiltinBackendReservesStubSectionName(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineAMD64, []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3})
	if err := object.AddSection(coff.NewSection(".text$cpl_dfr", []byte{0xcc})); err != nil {
		t.Fatal(err)
	}
	addFunction(t, object, object.GetSection(".text"), "resolve", 6)
	addImportRelocation(t, object, "__imp_KERNEL32$Sleep", 2, coff.RelAMD64Rel32)

	result, plan, err := ApplyBuiltin(object, defaultConfiguration(t, object, "resolve", MethodROR13))
	if err != nil {
		t.Fatal(err)
	}
	if got := result.GetSymbol(plan.Sites[0].StubSymbol).Section.Name; got != ".text$cpl_dfr$1" {
		t.Fatalf("stub section = %q", got)
	}
	if got := result.GetSection(".text$cpl_dfr").Data; !bytes.Equal(got, []byte{0xcc}) {
		t.Fatalf("colliding section changed: %x", got)
	}
}

func TestBuiltinBackendEncodesLongStringFrames(t *testing.T) {
	t.Parallel()
	module := strings.Repeat("M", 128)
	function := strings.Repeat("F", 128)
	for _, test := range []struct {
		name           string
		machine        coff.Machine
		code           []byte
		offset         uint32
		relocationType uint16
		resolver       string
		want           [][]byte
	}{
		{
			name: "x64", machine: coff.MachineAMD64,
			code: []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelAMD64Rel32, resolver: "resolve",
			want: [][]byte{
				{0x48, 0x81, 0xec, 0x30, 0x01, 0, 0},    // sub rsp, 304-byte frame
				{0xc6, 0x84, 0x24, 0xa0, 0, 0, 0, 0},    // zero module terminator through disp32
				{0x48, 0x8d, 0x94, 0x24, 0xa8, 0, 0, 0}, // lea rdx, [rsp+168]
			},
		},
		{
			name: "x86", machine: coff.MachineI386,
			code: []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelI386Dir32, resolver: "_resolve",
			want: [][]byte{{0x81, 0xc4, 0x18, 0x01, 0, 0}}, // add esp, 280-byte strings-and-args frame
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			object := resolverTestObject(t, test.machine, test.code)
			addFunction(t, object, object.GetSection(".text"), test.resolver, uint32(len(test.code)-1))
			addImportRelocation(t, object, "__imp_"+module+"$"+function, test.offset, test.relocationType)
			result, plan, err := ApplyBuiltin(object, defaultConfiguration(t, object, test.resolver, MethodStrings))
			if err != nil {
				t.Fatal(err)
			}
			stub := result.GetSymbol(plan.Sites[0].StubSymbol)
			for _, want := range test.want {
				if !bytes.Contains(stub.Section.Data[stub.Value:], want) {
					t.Fatalf("stub does not contain %x: %x", want, stub.Section.Data[stub.Value:])
				}
			}
		})
	}
}

func TestApplyBuiltinIsConcurrentAndDeterministic(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineAMD64, []byte{
		0xff, 0x15, 0, 0, 0, 0,
		0x4c, 0x8b, 0x15, 0, 0, 0, 0,
		0xc3,
	})
	text := object.GetSection(".text")
	addFunction(t, object, text, "resolve", 13)
	addImportRelocation(t, object, "__imp_KERNEL32$Sleep", 2, coff.RelAMD64Rel32)
	addImportRelocation(t, object, "__imp_USER32$MessageBoxA", 9, coff.RelAMD64Rel32)
	configuration := defaultConfiguration(t, object, "resolve", MethodStrings)

	const workers = 24
	outputs := make(chan []byte, workers)
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, _, err := ApplyBuiltin(object, configuration)
			if err != nil {
				errorsChannel <- err
				return
			}
			raw, err := coffwrite.Marshal(result)
			if err != nil {
				errorsChannel <- err
				return
			}
			outputs <- raw
		}()
	}
	wait.Wait()
	close(outputs)
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	var reference []byte
	for output := range outputs {
		if reference == nil {
			reference = output
			continue
		}
		if !bytes.Equal(output, reference) {
			t.Fatal("concurrent rewrites were not deterministic")
		}
	}
	if !bytes.Equal(object.GetSection(".text").Data[:2], []byte{0xff, 0x15}) {
		t.Fatal("concurrent rewrite mutated input")
	}
}

func TestApplyBuiltinIsIdempotentAfterImportsAreConsumed(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineAMD64, []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3})
	addFunction(t, object, object.GetSection(".text"), "resolve", 6)
	addImportRelocation(t, object, "__imp_KERNEL32$Sleep", 2, coff.RelAMD64Rel32)
	configuration := defaultConfiguration(t, object, "resolve", MethodROR13)

	first, firstPlan, err := ApplyBuiltin(object, configuration)
	if err != nil {
		t.Fatal(err)
	}
	second, secondPlan, err := ApplyBuiltin(first, configuration)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPlan.Sites) != 1 || len(secondPlan.Sites) != 0 {
		t.Fatalf("plans = %#v / %#v", firstPlan, secondPlan)
	}
	firstRaw, err := coffwrite.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := coffwrite.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Fatal("second application changed an already-consumed object")
	}
}

func FuzzApplyBuiltinCanonicalSite(f *testing.F) {
	f.Add(byte(0), uint32(0))
	f.Add(byte(3), uint32(0xfeedbeef))
	f.Add(byte(7), uint32(0xffffffff))
	f.Fuzz(func(t *testing.T, selector byte, addend uint32) {
		tests := []struct {
			machine        coff.Machine
			code           []byte
			offset         uint32
			relocationType uint16
		}{
			{machine: coff.MachineAMD64, code: []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelAMD64Rel32},
			{machine: coff.MachineAMD64, code: []byte{0xff, 0x25, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelAMD64Rel32},
			{machine: coff.MachineAMD64, code: []byte{0x4d, 0x8b, 0x3d, 0, 0, 0, 0, 0xc3}, offset: 3, relocationType: coff.RelAMD64Rel32},
			{machine: coff.MachineI386, code: []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelI386Dir32},
			{machine: coff.MachineI386, code: []byte{0xff, 0x25, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelI386Dir32},
			{machine: coff.MachineI386, code: []byte{0xa1, 0, 0, 0, 0, 0xc3}, offset: 1, relocationType: coff.RelI386Dir32},
			{machine: coff.MachineI386, code: []byte{0x8b, 0x3d, 0, 0, 0, 0, 0xc3}, offset: 2, relocationType: coff.RelI386Dir32},
		}
		test := tests[int(selector)%len(tests)]
		binary.LittleEndian.PutUint32(test.code[test.offset:test.offset+4], addend)
		object := resolverTestObject(t, test.machine, test.code)
		resolverName := fmt.Sprintf("resolve_%02x", selector)
		addFunction(t, object, object.GetSection(".text"), resolverName, uint32(len(test.code)-1))
		addImportRelocation(t, object, "__imp_KERNEL32$Sleep", test.offset, test.relocationType)
		result, plan, err := ApplyBuiltin(object, defaultConfiguration(t, object, resolverName, MethodROR13))
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Sites) != 1 || result.GetSymbol(plan.Sites[0].StubSymbol) == nil {
			t.Fatalf("result/plan = %#v / %#v", result, plan)
		}
	})
}

func assertBuiltinRelocations(t *testing.T, object *coff.Object, site Site, helperOffset uint32) {
	t.Helper()
	text := object.GetSection(site.SectionName)
	if len(text.Relocations) != 1 {
		t.Fatalf("site relocations = %#v", text.Relocations)
	}
	stub := object.GetSymbol(site.StubSymbol)
	if stub == nil || stub.Section == nil || stub.Section == text || stub.StorageClass != coff.SymbolClassStatic || !stub.IsFunction() {
		t.Fatalf("stub symbol = %#v", stub)
	}
	if stub.Section.Name != ".text$cpl_dfr" || !stub.Section.IsExecutable() || len(stub.Section.Relocations) != 1 {
		t.Fatalf("stub section = %#v", stub.Section)
	}
	wantType := coff.RelAMD64Rel32
	if object.Machine == coff.MachineI386 {
		wantType = coff.RelI386Rel32
	}
	if relocation := text.Relocations[0]; relocation.VirtualAddress != site.Offset || relocation.SymbolName != site.StubSymbol || relocation.Type != wantType {
		t.Fatalf("site relocation = %#v, want offset=%#x symbol=%q type=%#x", relocation, site.Offset, site.StubSymbol, wantType)
	}
	if relocation := stub.Section.Relocations[0]; relocation.VirtualAddress != stub.Value+helperOffset || relocation.SymbolName != site.Resolver.Function || relocation.Type != wantType {
		t.Fatalf("helper relocation = %#v, want offset=%#x symbol=%q type=%#x", relocation, stub.Value+helperOffset, site.Resolver.Function, wantType)
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	result, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestBuiltinPlanCloneRetainsStubSymbols(t *testing.T) {
	t.Parallel()
	plan := RewritePlan{Machine: coff.MachineAMD64, Sites: []Site{{StubSymbol: "stub"}}}
	if got := clonePlan(plan); !reflect.DeepEqual(got, plan) {
		t.Fatalf("clone = %#v, want %#v", got, plan)
	}
}
