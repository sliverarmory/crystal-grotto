// SPDX-License-Identifier: GPL-3.0-only

package resolver

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestConfigurationReplaySelectionAndClear(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineAMD64, []byte{0xc3})
	addFunction(t, object, object.GetSection(".text"), "moduleResolver", 0)
	addFunction(t, object, object.GetSection(".text"), "defaultResolver", 0)

	moduleDirective, err := ParseDirective([]string{"moduleResolver", "ror13", "kernel32, USER32, kernel32"}, false)
	if err != nil {
		t.Fatal(err)
	}
	defaultDirective, err := ParseDirective([]string{"defaultResolver", "strings"}, false)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := Replay(object, EmptyConfiguration(), []Directive{moduleDirective, defaultDirective})
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.HasResolvers() {
		t.Fatal("configuration unexpectedly empty")
	}
	if got, want := configuration.ResolverFunctions(), []string{"defaultResolver", "moduleResolver"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolverFunctions = %#v, want %#v", got, want)
	}
	selected, err := configuration.Resolve(Import{Symbol: "__imp_KERNEL32$Sleep", Module: "kernel32"})
	if err != nil || selected.Function != "moduleResolver" || selected.Method != MethodROR13 {
		t.Fatalf("module selection = %#v, %v", selected, err)
	}
	selected, err = configuration.Resolve(Import{Symbol: "__imp_ADVAPI32$Open", Module: "ADVAPI32"})
	if err != nil || selected.Function != "defaultResolver" || selected.Method != MethodStrings {
		t.Fatalf("default selection = %#v, %v", selected, err)
	}

	clear, err := ParseDirective([]string{"moduleResolver", "djb2"}, true)
	if err != nil {
		t.Fatal(err)
	}
	cleared, err := Replay(object, configuration, []Directive{clear})
	if err != nil {
		t.Fatal(err)
	}
	if len(cleared.Resolvers()) != 0 {
		t.Fatalf("+clear retained explicit resolvers: %#v", cleared.Resolvers())
	}
	defaultAfterClear, ok := cleared.Default()
	if !ok || defaultAfterClear.Function != "moduleResolver" || defaultAfterClear.Method != MethodDJB2 {
		t.Fatalf("default after +clear = %#v, %t", defaultAfterClear, ok)
	}
	if selected, _ := configuration.Resolve(Import{Module: "KERNEL32"}); selected.Function != "moduleResolver" {
		t.Fatal("Replay mutated base configuration")
	}
}

func TestConfigurationValidationAndCollisions(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineAMD64, []byte{0xc3})
	addFunction(t, object, object.GetSection(".text"), "resolve", 0)
	data := coff.NewSection(".data", []byte{0})
	if err := object.AddSection(data); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(coff.NewDataSymbol(data, "notFunction", 0)); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		arguments []string
		want      string
	}{
		{name: "too few", arguments: []string{"resolve"}, want: "expects 2 or 3"},
		{name: "too many", arguments: []string{"resolve", "ror13", "K", "extra"}, want: "expects 2 or 3"},
		{name: "bad method", arguments: []string{"resolve", "ROR13"}, want: "invalid DFR method"},
	}
	for _, test := range tests {
		if _, err := ParseDirective(test.arguments, false); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s error = %v, want %q", test.name, err, test.want)
		}
	}

	for _, test := range []struct {
		name      string
		directive Directive
		want      string
	}{
		{name: "missing", directive: Directive{Function: "missing", Method: MethodROR13, Default: true}, want: "does not exist"},
		{name: "not function", directive: Directive{Function: "notFunction", Method: MethodROR13, Default: true}, want: "is not a function"},
		{name: "bad direct method", directive: Directive{Function: "resolve", Method: "bad", Default: true}, want: "invalid DFR method"},
		{name: "default modules", directive: Directive{Function: "resolve", Method: MethodROR13, Default: true, Modules: []string{"K"}}, want: "default resolver cannot specify modules"},
	} {
		if _, err := Replay(object, EmptyConfiguration(), []Directive{test.directive}); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s error = %v, want %q", test.name, err, test.want)
		}
	}

	base, err := Replay(object, EmptyConfiguration(), []Directive{{Function: "resolve", Method: MethodROR13, Default: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(object, base, []Directive{{Function: "resolve", Method: MethodStrings, Modules: []string{"KERNEL32"}}}); err == nil || !strings.Contains(err.Error(), "uses a different contract") {
		t.Fatalf("contract collision error = %v", err)
	}
	// The same function/method may be declared repeatedly for different module sets.
	if _, err := Replay(object, base, []Directive{{Function: "resolve", Method: MethodROR13, Modules: []string{"KERNEL32"}}}); err != nil {
		t.Fatalf("same contract rejected: %v", err)
	}
	if _, err := Replay(nil, base, nil); err == nil {
		t.Fatal("nil object unexpectedly accepted")
	}
}

func TestConfigurationDefensiveCopiesAndPrecedence(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineAMD64, []byte{0xc3})
	addFunction(t, object, object.GetSection(".text"), "first", 0)
	addFunction(t, object, object.GetSection(".text"), "second", 0)
	configuration, err := Replay(object, EmptyConfiguration(), []Directive{
		{Function: "first", Method: MethodROR13, Modules: []string{"kernel32"}},
		{Function: "second", Method: MethodDJB2, Modules: []string{"KERNEL32"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := configuration.Resolve(Import{Module: "KeRnEl32"})
	if err != nil || selected.Function != "first" {
		t.Fatalf("first-declaration precedence = %#v, %v", selected, err)
	}
	copyOfResolvers := configuration.Resolvers()
	copyOfResolvers[0].modules[0] = "CHANGED"
	again := configuration.Resolvers()
	if got := again[0].Modules(); !reflect.DeepEqual(got, []string{"KERNEL32"}) {
		t.Fatalf("configuration exposed module storage: %#v", got)
	}
	if _, err := EmptyConfiguration().Resolve(Import{Symbol: "__imp_KERNEL32$Sleep", Module: "KERNEL32"}); err == nil || !strings.Contains(err.Error(), "No DFR resolver matches") {
		t.Fatalf("missing resolver error = %v", err)
	}
}

func TestAPITableImportCommandContract(t *testing.T) {
	t.Parallel()
	defaults := DefaultAPITable()
	if want := []string{"LoadLibraryA", "GetProcAddress"}; !reflect.DeepEqual(defaults, want) {
		t.Fatalf("DefaultAPITable = %#v, want %#v", defaults, want)
	}
	defaults[0] = "changed"
	if DefaultAPITable()[0] != "LoadLibraryA" {
		t.Fatal("DefaultAPITable exposed package storage")
	}

	apis, err := ParseAPITable("LoadLibraryA, GetProcAddress, BeaconPrintf")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"LoadLibraryA", "GetProcAddress", "BeaconPrintf"}; !reflect.DeepEqual(apis, want) {
		t.Fatalf("ParseAPITable = %#v, want %#v", apis, want)
	}
	input := []string{"LoadLibraryA", "GetProcAddress"}
	validated, err := ValidateAPITable(input)
	if err != nil {
		t.Fatal(err)
	}
	validated[0] = "changed"
	if input[0] != "LoadLibraryA" {
		t.Fatal("ValidateAPITable returned aliased storage")
	}
	for _, test := range []struct {
		value string
		want  string
	}{
		{value: "", want: "LoadLibraryA is required as the first API entry."},
		{value: "GetProcAddress, LoadLibraryA", want: "LoadLibraryA is required as the first API entry."},
		{value: "LoadLibraryA", want: "GetProcAddress is required as the second API entry."},
	} {
		if _, err := ParseAPITable(test.value); err == nil || err.Error() != test.want {
			t.Errorf("ParseAPITable(%q) error = %v, want %q", test.value, err, test.want)
		}
	}
}
