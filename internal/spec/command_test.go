// SPDX-License-Identifier: GPL-3.0-only

package spec

import (
	"reflect"
	"testing"
)

func TestParseCommand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		command string
		args    []string
		types   []string
		opts    []string
	}{
		{name: "bare", input: "export", command: "export", args: nil, types: []string{}, opts: []string{}},
		{name: "quotes", input: `pack "$X" "a z" "hello world"`, command: "pack", args: []string{"$X", "a z", "hello world"}, types: []string{"string", "string", "string"}, opts: []string{}},
		{name: "comment", input: `push $DATA # ignored`, command: "push", args: []string{"$DATA"}, types: []string{"string"}, opts: []string{}},
		{name: "options", input: `make object +mutate +relax`, command: "make", args: []string{"object"}, types: []string{"string"}, opts: []string{"+mutate", "+relax"}},
		{name: "capture rest", input: `foreach "a, b": echo %_ here`, command: "foreach", args: []string{"a, b", "echo %_ here"}, types: []string{"string", "string"}, opts: []string{}},
		{name: "custom quote", input: `echo,' 'hello world'`, command: "echo", args: []string{"hello world"}, types: []string{"string"}, opts: []string{}},
		{name: "variable concat", input: `echo %name <> ".bin"`, command: "echo", args: []string{"%name.bin"}, types: []string{"var <> string"}, opts: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseCommand(tt.input)
			if got.Name() != tt.command {
				t.Fatalf("Name() = %q, want %q", got.Name(), tt.command)
			}
			if !reflect.DeepEqual(got.RawArguments(), tt.args) {
				t.Errorf("RawArguments() = %#v, want %#v", got.RawArguments(), tt.args)
			}
			if !reflect.DeepEqual(got.ArgumentTypes(), tt.types) {
				t.Errorf("ArgumentTypes() = %#v, want %#v", got.ArgumentTypes(), tt.types)
			}
			if !reflect.DeepEqual(got.Options(), tt.opts) {
				t.Errorf("Options() = %#v, want %#v", got.Options(), tt.opts)
			}
		})
	}
}

func TestCommandResolvesVariablesAndConcat(t *testing.T) {
	t.Parallel()
	command := ParseCommand(`echo "prefix-" <> %name <> "-suffix"`)
	got, err := command.Arguments(ResolverFunc(func(name string) (string, error) {
		if name == "%name" {
			return "grotto", nil
		}
		return "", nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"prefix-grotto-suffix"}; !reflect.DeepEqual(got.Args, want) {
		t.Fatalf("Arguments() = %#v, want %#v", got.Args, want)
	}
}

func FuzzParseCommand(f *testing.F) {
	for _, seed := range []string{"export", `echo "hello"`, `foreach "a,b": echo %_`, `make object +relax`, ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		command := ParseCommand(input)
		_, _ = command.Arguments(nil)
		_, _ = command.FullCommand(nil)
		_ = command.ArgumentTypes()
	})
}
