// SPDX-License-Identifier: GPL-3.0-only

package rulegen

import (
	"strings"
	"testing"
	"time"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/spec"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestRulePrinterExactFormatting(t *testing.T) {
	rule, err := NewRule([]RuleInstruction{
		{
			Instruction: x86.Instruction{Bytes: []byte{0x48, 0x89, 0xe5}, Mnemonic: "mov", Operands: "rbp, rsp"},
			Score:       2,
		},
		{
			Instruction: x86.Instruction{Bytes: []byte{0xe8, 0x2a, 0, 0, 0}, Mnemonic: "call", Operands: "0x32"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	printer := RulePrinter{
		Metadata: spec.Metadata{
			Name: "Trade Craft", Description: "detects things", Author: "Operator",
			Reference: "https://example.invalid", License: "BSD-3-Clause",
		},
		Args:    Args{Agreement: 1},
		Machine: coff.MachineAMD64,
		Now: func() time.Time {
			return time.Date(2025, time.January, 2, 23, 0, 0, 0, time.FixedZone("test", -8*60*60))
		},
	}
	name, err := printer.RuleName("12345678-1234-4234-8234-123456789abc")
	if err != nil {
		t.Fatal(err)
	}
	if name != "Trade_Craft_12345678" {
		t.Fatalf("RuleName = %q", name)
	}
	got, err := printer.Print(name, []FunctionRules{{Name: "_entry-point", Rules: []Rule{rule}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "" +
		"rule Trade_Craft_12345678 {\n" +
		"\tmeta:\n" +
		"\t\tdescription = \"Trade Craft: detects things\"\n" +
		"\t\tauthor = \"Operator\"\n" +
		"\t\tdate = \"2025-01-02\"\n" +
		"\t\treference = \"https://example.invalid\"\n" +
		"\t\tarch_context = \"x64\"\n" +
		"\t\tscan_context = \"file, memory\"\n" +
		"\t\tos = \"windows\"\n" +
		"\t\tlicense = \"BSD-3-Clause\"\n" +
		"\t\tgenerator = \"Crystal Palace\"\n" +
		"\tstrings:\n" +
		"\t\t// ----------------------------------------\n" +
		"\t\t// Function: _entry-point\n" +
		"\t\t// ----------------------------------------\n" +
		"\t\t/*\n" +
		"\t\t * 48 89 E5                      mov rbp, rsp\n" +
		"\t\t * E8 2A 00 00 00                call 0x32\n" +
		"\t\t * (Score: 6)\n" +
		"\t\t */\n" +
		"\t\t$r0_entry_point = { 48 89 E5 E8 ?? ?? ?? ?? }\n\n" +
		"\tcondition:\n" +
		"\t\tany of them\n" +
		"}\n\n"
	if string(got) != want {
		t.Fatalf("Print mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}
}

func TestRulePrinterConditionsAndNames(t *testing.T) {
	rule, err := NewRule([]RuleInstruction{{Instruction: x86.Instruction{Bytes: []byte{0x90}, Mnemonic: "nop"}}})
	if err != nil {
		t.Fatal(err)
	}
	printer := RulePrinter{
		Metadata: spec.Metadata{Name: "Ends!!!___"},
		Args:     Args{Agreement: 2},
		Machine:  coff.MachineI386,
		Now:      func() time.Time { return time.Unix(0, 0).UTC() },
	}
	name, err := printer.RuleName("abcdef01-rest")
	if err != nil {
		t.Fatal(err)
	}
	if name != "Ends_abcdef01" {
		t.Fatalf("sanitized name = %q", name)
	}
	got, err := printer.Print(name, []FunctionRules{{Name: "f", Rules: []Rule{rule}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "\t\tall of them\n") {
		t.Fatalf("agreement condition missing:\n%s", got)
	}
	printer.Args.Name = "explicit-name"
	name, err = printer.RuleName("abcdef01-rest")
	if err != nil || name != "explicit-name_abcdef01" {
		t.Fatalf("explicit RuleName = %q, %v", name, err)
	}
	if _, err := printer.RuleName("short"); err == nil {
		t.Fatal("short UUID succeeded")
	}
	if got, err := printer.Print("unused", nil); err != nil || len(got) != 0 {
		t.Fatalf("empty Print = %q, %v", got, err)
	}
}
