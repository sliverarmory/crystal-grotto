// SPDX-License-Identifier: GPL-3.0-only

package rulegen

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseArgsDefaults(t *testing.T) {
	got, err := ParseArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultArgs()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseArgs(nil) = %#v, want %#v", got, want)
	}
	if !got.Targets("anything") {
		t.Fatal("empty function list did not target all functions")
	}
}

func TestParseArgsFullAndIgnoresExtras(t *testing.T) {
	got, err := ParseArgs([]string{"named", "3", "2", "4-20", " alpha, beta,alpha,", "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	want := Args{
		Name: "named", MaxRules: 3, Agreement: 2,
		MinLength: 4, MaxLength: 20, Functions: []string{"alpha", "beta"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseArgs = %#v, want %#v", got, want)
	}
	if !got.Targets("beta") || got.Targets("gamma") {
		t.Fatalf("unexpected target filtering: %#v", got.Functions)
	}
}

func TestParseArgsErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"max integer", []string{"", "nope"}, "maxrules must be integer"},
		{"minus one sentinel", []string{"", "-1"}, "maxrules must be integer"},
		{"agreement integer", []string{"", "2", "x"}, "minagree must be integer"},
		{"range format", []string{"", "2", "1", "12"}, "not in ##-## format"},
		{"range order", []string{"", "2", "1", "12-4"}, "Invalid range"},
		{"agreement limit", []string{"", "2", "3"}, "agreement 3 is larger than max rules 2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseArgs(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseArgs error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestArgsKeepsUpstreamNegativeIntegerBehavior(t *testing.T) {
	got, err := ParseArgs([]string{"", "-2", "-3"})
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxRules != -2 || got.Agreement != -3 {
		t.Fatalf("unexpected negative values: %#v", got)
	}
}
