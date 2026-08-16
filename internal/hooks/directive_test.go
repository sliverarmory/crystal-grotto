// SPDX-License-Identifier: GPL-3.0-only

package hooks

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseDirectiveAritiesAndDefensiveArguments(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		kind       DirectiveKind
		needsBytes bool
		resource   string
	}{
		{"attach", []string{"KERNEL32$Sleep", "wrapper"}, Attach, false, ""},
		{"redirect", []string{"target", "wrapper"}, Redirect, false, ""},
		{"addhook", []string{"KERNEL32$Sleep"}, AddHook, false, ""},
		{"addhook", []string{"KERNEL32$Sleep", "wrapper"}, AddHook, false, ""},
		{"filterhooks", []string{"$OBJECT"}, FilterHooks, true, "$OBJECT"},
		{"preserve", []string{"target", "a,b"}, Preserve, false, ""},
		{"protect", []string{"a,b"}, Protect, false, ""},
		{"optout", []string{"a", "b,c"}, OptOut, false, ""},
		{"intrinsic", []string{"__name", "$BYTES"}, Intrinsic, true, "$BYTES"},
		{"catch", []string{"function", "handler"}, Catch, false, ""},
	}
	for _, test := range tests {
		t.Run(test.name+"/"+string(test.kind), func(t *testing.T) {
			input := append([]string(nil), test.args...)
			got, err := Parse(test.name, input)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind() != test.kind || got.NeedsBytes() != test.needsBytes || got.ResourceRef() != test.resource {
				t.Fatalf("directive = %#v", got)
			}
			if !reflect.DeepEqual(got.Arguments(), test.args) {
				t.Fatalf("arguments = %#v, want %#v", got.Arguments(), test.args)
			}
			if len(input) > 0 {
				input[0] = "changed"
				returned := got.Arguments()
				returned[0] = "also changed"
				if got.Arguments()[0] != test.args[0] {
					t.Fatal("directive exposed argument storage")
				}
			}
		})
	}
}

func TestParseDirectiveErrors(t *testing.T) {
	tests := []struct {
		command string
		args    []string
		want    string
	}{
		{"unknown", nil, "unsupported directive"},
		{"attach", []string{"one"}, "expects 2 arguments"},
		{"addhook", nil, "expects 1 to 2 arguments"},
		{"addhook", []string{"a", "b", "c"}, "expects 1 to 2 arguments"},
		{"protect", []string{"a", "b"}, "expects 1 arguments"},
	}
	for _, test := range tests {
		_, err := Parse(test.command, test.args)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("Parse(%q, %#v) error = %v, want %q", test.command, test.args, err, test.want)
		}
	}
}

func TestParseModuleFunctionCompatibility(t *testing.T) {
	tests := []struct {
		target    string
		module    string
		function  string
		canonical string
		valid     bool
	}{
		{"kernel32$Sleep", "kernel32", "Sleep", "KERNEL32$Sleep", true},
		{"A$B$ignored", "A", "B", "A$B", true},
		{"$Function", "", "Function", "$Function", true},
		{"A$$ignored", "A", "", "A$", true},
		{"missing", "", "", "", false},
		{"A$", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, test := range tests {
		got, err := ParseModuleFunction(test.target)
		if !test.valid {
			if err == nil {
				t.Fatalf("ParseModuleFunction(%q) succeeded: %#v", test.target, got)
			}
			continue
		}
		if err != nil || got.Module != test.module || got.Function != test.function || got.Target() != test.canonical {
			t.Fatalf("ParseModuleFunction(%q) = %#v, %v", test.target, got, err)
		}
	}
}

func FuzzParseModuleFunction(f *testing.F) {
	f.Add("KERNEL32$Sleep")
	f.Add("A$B$C")
	f.Add("")
	f.Fuzz(func(t *testing.T, target string) {
		parsed, err := ParseModuleFunction(target)
		if err == nil && !strings.Contains(target, "$") {
			t.Fatalf("accepted target without separator: %#v", parsed)
		}
	})
}
