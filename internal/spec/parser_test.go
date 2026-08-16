// SPDX-License-Identifier: GPL-3.0-only

package spec

import (
	"strings"
	"testing"
)

func TestParseSpecMetadataAndLabels(t *testing.T) {
	t.Parallel()
	s, err := Parse("/tmp/example.spec", `
name "Example"
author "Crystal Grotto"
x86:
  push $DATA
x64:
  push $DATA
`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.Name(), "Example"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
	if !s.Targets("x86") || !s.Targets("x64") {
		t.Fatalf("targets missing: %#v", s.labels)
	}
}

func TestParseSpecCollectsErrors(t *testing.T) {
	t.Parallel()
	_, err := Parse("bad.spec", `
push $DATA
arm64:
wat nope
x64:
make pic +shatter +unwind
`)
	if err == nil {
		t.Fatal("Parse() succeeded, want error")
	}
	for _, want := range []string{
		"Commands must exist under an 'x86:' or 'x64:' label at line 2",
		"Invalid label 'arm64'",
		"Invalid command 'wat'",
		"Options +shatter and +unwind are not compatible",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestParseEmbeddedForeachCommand(t *testing.T) {
	t.Parallel()
	s, err := Parse("loop.spec", `x64:
foreach "a, b": echo %_
push $DATA
`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(s.labels["x64"]), 3; got != want {
		t.Fatalf("instruction count = %d, want %d", got, want)
	}
}

func TestParseEmbeddedNextCommand(t *testing.T) {
	t.Parallel()
	s, err := Parse("next.spec", "x64:\nset \"%items\" \"a, b\"\nnext \"%items\": echo %_\npush $NULL\n")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(s.labels["x64"]), 4; got != want {
		t.Fatalf("instruction count = %d, want %d", got, want)
	}
}

func TestParseValidatesRuleAndRewriteArguments(t *testing.T) {
	t.Parallel()
	_, err := Parse("bad-arguments.spec", `x64:
rule "bad" 2 3 10-16
ised replace "PUSH r64" $CODE +first +last
`)
	if err == nil {
		t.Fatal("Parse() succeeded, want error")
	}
	for _, want := range []string{
		"agreement 3 is larger than max rules 2",
		"ised: both +first and +last set",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestEmptyLabelMayBeRepeatedForUpstreamCompatibility(t *testing.T) {
	t.Parallel()
	if _, err := Parse("empty.spec", "x64:\nx64:\n  push $NULL\n"); err != nil {
		t.Fatal(err)
	}
}

func FuzzParseSpec(f *testing.F) {
	f.Add("fuzz.spec", "x64:\npush $DATA\n")
	f.Add("fuzz.spec", "name \"x\"\n")
	f.Fuzz(func(t *testing.T, file, content string) {
		_, _ = Parse(file, content)
	})
}
