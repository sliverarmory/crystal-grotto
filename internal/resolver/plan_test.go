// SPDX-License-Identifier: GPL-3.0-only

package resolver

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestBuildPlanRecognizesX64Forms(t *testing.T) {
	t.Parallel()
	code := []byte{
		0xff, 0x15, 0, 0, 0, 0, // call qword ptr [rip+disp32]
		0xff, 0x25, 0, 0, 0, 0, // jmp qword ptr [rip+disp32]
		0x48, 0x8b, 0x05, 0, 0, 0, 0, // mov rax, [rip+disp32]
		0x4c, 0x8b, 0x15, 0, 0, 0, 0, // mov r10, [rip+disp32]
		0xc3,
	}
	object := resolverTestObject(t, coff.MachineAMD64, code)
	addFunction(t, object, object.GetSection(".text"), "go", 0)
	addFunction(t, object, object.GetSection(".text"), "resolve", 26)
	addImportRelocation(t, object, "__imp_KERNEL32$Sleep", 2, coff.RelAMD64Rel32)
	addImportRelocation(t, object, "__imp_USER32$ExitWindowsEx", 8, coff.RelAMD64Rel32)
	addImportRelocation(t, object, "__imp_ADVAPI32$OpenProcessToken", 15, coff.RelAMD64Rel32)
	addImportRelocation(t, object, "__imp_KERNEL32$GetTickCount", 22, coff.RelAMD64Rel32)
	configuration := defaultConfiguration(t, object, "resolve", MethodROR13)

	plan, err := BuildPlan(object, configuration)
	if err != nil {
		t.Fatal(err)
	}
	forms := make([]Form, 0, len(plan.Sites))
	destinations := make([]string, 0, len(plan.Sites))
	for _, site := range plan.Sites {
		forms = append(forms, site.Form)
		destinations = append(destinations, site.Destination)
		if site.Resolver.Function != "resolve" || site.Invocation.Method != MethodROR13 {
			t.Fatalf("site resolver = %#v", site)
		}
	}
	if want := []Form{FormCall64, FormJump64, FormMove64, FormMove64}; !reflect.DeepEqual(forms, want) {
		t.Fatalf("forms = %#v, want %#v", forms, want)
	}
	if want := []string{"rax", "rax", "rax", "r10"}; !reflect.DeepEqual(destinations, want) {
		t.Fatalf("destinations = %#v, want %#v", destinations, want)
	}
}

func TestBuildPlanRecognizesX86FormsAndDecorations(t *testing.T) {
	t.Parallel()
	code := []byte{
		0xff, 0x15, 0, 0, 0, 0,
		0xff, 0x25, 0, 0, 0, 0,
		0xa1, 0, 0, 0, 0,
		0x8b, 0x0d, 0, 0, 0, 0,
		0xc3,
	}
	object := resolverTestObject(t, coff.MachineI386, code)
	addFunction(t, object, object.GetSection(".text"), "_go", 0)
	addFunction(t, object, object.GetSection(".text"), "_resolve", 23)
	addImportRelocation(t, object, "__imp__KERNEL32$Sleep@4", 2, coff.RelI386Dir32)
	addImportRelocation(t, object, "__imp__USER32$ExitWindowsEx@8", 8, coff.RelI386Dir32)
	addImportRelocation(t, object, "__imp__ADVAPI32$OpenProcessToken@12", 13, coff.RelI386Dir32)
	addImportRelocation(t, object, "__imp__KERNEL32$GetTickCount@0", 19, coff.RelI386Dir32)
	configuration := defaultConfiguration(t, object, "_resolve", MethodStrings)

	plan, err := BuildPlan(object, configuration)
	if err != nil {
		t.Fatal(err)
	}
	forms := make([]Form, 0, len(plan.Sites))
	destinations := make([]string, 0, len(plan.Sites))
	for _, site := range plan.Sites {
		forms = append(forms, site.Form)
		destinations = append(destinations, site.Destination)
	}
	if want := []Form{FormCall32, FormJump32, FormMoveEAX, FormMove32}; !reflect.DeepEqual(forms, want) {
		t.Fatalf("forms = %#v, want %#v", forms, want)
	}
	if want := []string{"eax", "eax", "eax", "ecx"}; !reflect.DeepEqual(destinations, want) {
		t.Fatalf("destinations = %#v, want %#v", destinations, want)
	}
	if plan.Sites[0].Import.Function != "Sleep" {
		t.Fatalf("x86 decoration remains: %#v", plan.Sites[0].Import)
	}
}

func TestBuildPlanRejectsMalformedAndUnsupportedSites(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		machine    coff.Machine
		code       []byte
		offset     uint32
		relocation uint16
		symbol     string
		mutate     func(*coff.Object)
		want       string
		is         error
	}{
		{name: "x64 direct call", machine: coff.MachineAMD64, code: []byte{0xe8, 0, 0, 0, 0, 0xc3}, offset: 1, relocation: coff.RelAMD64Rel32, symbol: "__imp_KERNEL32$Sleep", want: "expected FF/2", is: ErrUnsupportedForm},
		{name: "x64 relocation type", machine: coff.MachineAMD64, code: []byte{0xff, 0x15, 0, 0, 0, 0}, offset: 2, relocation: coff.RelAMD64Addr32NB, symbol: "__imp_KERNEL32$Sleep", want: "relocation type", is: ErrUnsupportedForm},
		{name: "x86 eax non-moffs", machine: coff.MachineI386, code: []byte{0x8b, 0x05, 0, 0, 0, 0}, offset: 2, relocation: coff.RelI386Dir32, symbol: "__imp_KERNEL32$Sleep", want: "non-EAX", is: ErrUnsupportedForm},
		{name: "out of bounds", machine: coff.MachineAMD64, code: []byte{0xff, 0x15, 0, 0, 0}, offset: 2, relocation: coff.RelAMD64Rel32, symbol: "__imp_KERNEL32$Sleep", want: "exceeds"},
		{name: "missing module", machine: coff.MachineAMD64, code: []byte{0xff, 0x15, 0, 0, 0, 0}, offset: 2, relocation: coff.RelAMD64Rel32, symbol: "__imp_Custom", want: "not in MODULE$Function format"},
		{name: "wrong parent", machine: coff.MachineAMD64, code: []byte{0xff, 0x15, 0, 0, 0, 0}, offset: 2, relocation: coff.RelAMD64Rel32, symbol: "__imp_KERNEL32$Sleep", mutate: func(object *coff.Object) { object.GetSection(".text").Relocations[0].Section = nil }, want: "parent does not match"},
		{name: "nil relocation", machine: coff.MachineAMD64, code: []byte{0xff, 0x15, 0, 0, 0, 0}, offset: 2, relocation: coff.RelAMD64Rel32, symbol: "__imp_KERNEL32$Sleep", mutate: func(object *coff.Object) { object.GetSection(".text").Relocations[0] = nil }, want: "nil relocation"},
		{name: "nil section", machine: coff.MachineAMD64, code: []byte{0xff, 0x15, 0, 0, 0, 0}, offset: 2, relocation: coff.RelAMD64Rel32, symbol: "__imp_KERNEL32$Sleep", mutate: func(object *coff.Object) { object.Sections[0] = nil }, want: "section 0 is nil"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			object := resolverTestObject(t, test.machine, test.code)
			addFunction(t, object, object.GetSection(".text"), "resolve", 0)
			addImportRelocation(t, object, test.symbol, test.offset, test.relocation)
			if test.mutate != nil {
				test.mutate(object)
			}
			configuration := defaultConfiguration(t, object, "resolve", MethodROR13)
			_, err := BuildPlan(object, configuration)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
			if test.is != nil && !errors.Is(err, test.is) {
				t.Fatalf("errors.Is(%v, %v) = false", err, test.is)
			}
		})
	}

	arm, err := coff.NewObject(coff.MachineARM64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(arm, EmptyConfiguration()); err == nil || !strings.Contains(err.Error(), "unsupported machine") {
		t.Fatalf("ARM64 error = %v", err)
	}
	if _, err := BuildPlan(nil, EmptyConfiguration()); err == nil {
		t.Fatal("nil object unexpectedly accepted")
	}
}

func TestBuildPlanResolverSelectionErrorsAndNoOp(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineAMD64, []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3})
	addFunction(t, object, object.GetSection(".text"), "resolve", 6)
	addImportRelocation(t, object, "__imp_USER32$MessageBoxA", 2, coff.RelAMD64Rel32)

	plan, err := BuildPlan(object, EmptyConfiguration())
	if err != nil || len(plan.Sites) != 0 {
		t.Fatalf("no-resolver plan = %#v, %v", plan, err)
	}
	configuration, err := Replay(object, EmptyConfiguration(), []Directive{{Function: "resolve", Method: MethodROR13, Modules: []string{"KERNEL32"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(object, configuration); err == nil || !strings.Contains(err.Error(), "No DFR resolver matches") {
		t.Fatalf("selection error = %v", err)
	}
}

func TestConfigurationAndPlanningAreConcurrentReadSafe(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineAMD64, []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3})
	addFunction(t, object, object.GetSection(".text"), "resolve", 6)
	addImportRelocation(t, object, "__imp_KERNEL32$Sleep", 2, coff.RelAMD64Rel32)
	configuration := defaultConfiguration(t, object, "resolve", MethodROR13)

	const workers = 32
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			plan, err := BuildPlan(object, configuration)
			if err != nil {
				errorsChannel <- err
				return
			}
			if len(plan.Sites) != 1 || plan.Sites[0].Invocation.FunctionHash != 0xdb2d49b0 {
				errorsChannel <- errors.New("unexpected concurrent plan")
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}
