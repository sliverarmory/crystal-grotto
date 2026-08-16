// SPDX-License-Identifier: GPL-3.0-only

package ised

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseDirectiveMatchesUpstream(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    []string
		options []string
		content []byte
		want    Command
	}{
		{
			name: "insert defaults after and last", args: []string{"insert", "PUSH r64", "$CODE"}, content: []byte{0x90},
			want: Command{Verb: VerbInsert, Patterns: []string{"PUSH r64"}, Variable: "$CODE", Content: []byte{0x90}},
		},
		{
			name: "replace sequence first safe", args: []string{"replace", "PUSH", "MOV r64, r64", "$CODE"}, options: []string{"+first", "+safe"}, content: []byte{0xcc},
			want: Command{Verb: VerbReplace, Patterns: []string{"PUSH", "MOV r64, r64"}, Variable: "$CODE", Options: CommandOptions{First: true, Safe: true}, Content: []byte{0xcc}},
		},
		{
			name: "split before", args: []string{"insert", "NOP", "$CODE"}, options: []string{"+before", "+split"}, content: []byte{0xcc},
			want: Command{Verb: VerbInsert, Patterns: []string{"NOP"}, Variable: "$CODE", Options: CommandOptions{Before: true, Split: true}, Content: []byte{0xeb, 0, 0xcc}},
		},
		{
			name: "split first", args: []string{"replace", "NOP", "$CODE"}, options: []string{"+first", "+split"}, content: []byte{0xcc},
			want: Command{Verb: VerbReplace, Patterns: []string{"NOP"}, Variable: "$CODE", Options: CommandOptions{First: true, Split: true}, Content: []byte{0xeb, 0, 0xcc}},
		},
		{
			name: "split default suffix", args: []string{"replace", "NOP", "$CODE"}, options: []string{"+after", "+last", "+split"}, content: []byte{0xcc},
			want: Command{Verb: VerbReplace, Patterns: []string{"NOP"}, Variable: "$CODE", Options: CommandOptions{After: true, Last: true, Split: true}, Content: []byte{0xcc, 0xeb, 0}},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			arguments := append([]string(nil), test.args...)
			options := append([]string(nil), test.options...)
			content := append([]byte(nil), test.content...)
			got, err := ParseDirective(arguments, options, content)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ParseDirective = %#v, want %#v", got, test.want)
			}
			if len(arguments) != 0 {
				arguments[0] = "changed"
			}
			if len(content) != 0 {
				content[0] ^= 0xff
			}
			if got.Verb != test.want.Verb || !bytes.Equal(got.Content, test.want.Content) {
				t.Fatal("parsed command aliases caller input")
			}
		})
	}
}

func TestParseDirectiveErrorsMatchUpstream(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    []string
		options []string
		want    string
	}{
		{name: "empty", want: "Invalid verb ''"},
		{name: "verb", args: []string{"delete", "NOP", "$X"}, want: "Invalid verb 'delete'"},
		{name: "variable", args: []string{"insert", "NOP", ""}, want: "Specify a variable"},
		{name: "pattern", args: []string{"insert", "$X"}, want: "Missing pattern"},
		{name: "first last", args: []string{"insert", "NOP", "$X"}, options: []string{"+first", "+last"}, want: "both +first and +last"},
		{name: "before after", args: []string{"insert", "NOP", "$X"}, options: []string{"+before", "+after"}, want: "both +before and +after"},
		{name: "option", args: []string{"insert", "NOP", "$X"}, options: []string{"+mystery"}, want: "Invalid option '+mystery'"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseDirective(test.args, test.options, nil)
			if !errors.Is(err, ErrInvalidCommand) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %T %v, want ErrInvalidCommand containing %q", err, err, test.want)
			}
			var commandError *CommandError
			if !errors.As(err, &commandError) {
				t.Fatalf("error type = %T", err)
			}
		})
	}
}

func TestReplayIsTransactionalAndDefensive(t *testing.T) {
	t.Parallel()
	base, err := Replay(EmptyConfiguration(), []Directive{{
		Arguments: []string{"replace", "NOP", "$ONE"}, Content: []byte{0x90},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if base.IsEmpty() || EmptyConfiguration().IsEmpty() != true {
		t.Fatal("configuration emptiness mismatch")
	}
	updated, err := Replay(base, []Directive{{
		Arguments: []string{"insert", "RET", "$TWO"}, Options: []string{"+before"}, Content: []byte{0xcc},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Commands()) != 1 || len(updated.Commands()) != 2 {
		t.Fatalf("command counts = %d / %d", len(base.Commands()), len(updated.Commands()))
	}
	commands := updated.Commands()
	commands[0].Patterns[0] = "changed"
	commands[0].Content[0] = 0
	if again := updated.Commands(); again[0].Patterns[0] != "NOP" || again[0].Content[0] != 0x90 {
		t.Fatal("Commands returned shared storage")
	}
	failed, err := Replay(base, []Directive{
		{Arguments: []string{"insert", "RET", "$OK"}},
		{Arguments: []string{"delete", "RET", "$BAD"}},
	})
	if err == nil || !failed.IsEmpty() || len(base.Commands()) != 1 {
		t.Fatalf("transactional replay = %#v, %v", failed, err)
	}
}

func FuzzParseDirective(f *testing.F) {
	f.Add("insert", "NOP", "$X", "+split", []byte{0x90})
	f.Add("replace", "PUSH r64", "$CODE", "+safe", []byte{0xcc})
	f.Fuzz(func(t *testing.T, verb, pattern, variable, option string, content []byte) {
		if len(content) > 256 {
			content = content[:256]
		}
		_, _ = ParseDirective([]string{verb, pattern, variable}, []string{option}, content)
	})
}
