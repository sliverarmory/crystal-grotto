// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package rulegen

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/spec"
)

const rawByteColumnWidth = 10

// FunctionRules preserves function and block order for deterministic output.
type FunctionRules struct {
	Name  string
	Rules []Rule
}

// RulePrinter renders the byte-for-byte-stable subset of the upstream YARA
// layout. Now is injectable; nil selects time.Now.
type RulePrinter struct {
	Metadata spec.Metadata
	Args     Args
	Machine  coff.Machine
	Now      func() time.Time
}

// RuleName creates the upstream name from a UUID string. The UUID must expose
// at least the eight-character prefix used by Crystal Palace.
func (p RulePrinter) RuleName(uuid string) (string, error) {
	if len(uuid) < 8 {
		return "", fmt.Errorf("rulegen: UUID %q is shorter than eight characters", uuid)
	}
	base := p.Args.Name
	if base == "" {
		base = p.Metadata.Name
		if base == "" {
			base = "TCG"
		}
		base = sanitizeRuleBase(base)
	}
	return base + "_" + uuid[:8], nil
}

// Print renders groups under an already-selected rule name. Empty groups
// produce an empty byte slice, matching the upstream printer.
func (p RulePrinter) Print(ruleName string, groups []FunctionRules) ([]byte, error) {
	count := 0
	for _, group := range groups {
		count += len(group.Rules)
	}
	if count == 0 {
		return []byte{}, nil
	}
	if p.Machine != coff.MachineI386 && p.Machine != coff.MachineAMD64 {
		return nil, fmt.Errorf("rulegen: cannot print rules for %s", p.Machine)
	}
	if ruleName == "" {
		return nil, fmt.Errorf("rulegen: rule name is empty")
	}
	now := p.Now
	if now == nil {
		now = time.Now
	}

	var output strings.Builder
	fmt.Fprintf(&output, "rule %s {\n", ruleName)
	output.WriteString("\tmeta:\n")
	if p.Metadata.Name != "" && p.Metadata.Description != "" {
		printMeta(&output, "description", p.Metadata.Name+": "+p.Metadata.Description)
	} else if p.Metadata.Name != "" {
		printMeta(&output, "description", "Detects "+p.Metadata.Name)
	}
	printMeta(&output, "author", p.Metadata.Author)
	printMeta(&output, "date", now().Format("2006-01-02"))
	printMeta(&output, "reference", p.Metadata.Reference)
	printMeta(&output, "arch_context", p.Machine.String())
	printMeta(&output, "scan_context", "file, memory")
	printMeta(&output, "os", "windows")
	printMeta(&output, "license", p.Metadata.License)
	printMeta(&output, "generator", "Crystal Palace")
	output.WriteString("\tstrings:\n")

	ruleNumber := 0
	for _, group := range groups {
		if len(group.Rules) == 0 {
			continue
		}
		output.WriteString("\t\t// ----------------------------------------\n")
		fmt.Fprintf(&output, "\t\t// Function: %s\n", group.Name)
		output.WriteString("\t\t// ----------------------------------------\n")
		for _, rule := range group.Rules {
			output.WriteString("\t\t/*\n")
			for _, instruction := range rule.Instructions() {
				output.WriteString("\t\t * ")
				output.WriteString(formatCommentInstruction(instruction))
				output.WriteByte('\n')
			}
			fmt.Fprintf(&output, "\t\t * (Score: %d)\n", rule.Score())
			output.WriteString("\t\t */\n")
			fmt.Fprintf(&output, "\t\t$r%d_%s = { ", ruleNumber, sanitizeSignatureName(group.Name))
			content, wildcards := rule.Content(), rule.Wildcards()
			for index, value := range content {
				if wildcards[index] {
					output.WriteString("?? ")
				} else {
					fmt.Fprintf(&output, "%02X ", value)
				}
			}
			output.WriteString("}\n\n")
			ruleNumber++
		}
	}

	output.WriteString("\tcondition:\n")
	switch {
	case p.Args.Agreement == 1:
		output.WriteString("\t\tany of them\n")
	case p.Args.Agreement >= count:
		output.WriteString("\t\tall of them\n")
	default:
		fmt.Fprintf(&output, "\t\t%d of them\n", p.Args.Agreement)
	}
	output.WriteString("}\n\n")
	return []byte(output.String()), nil
}

func printMeta(output *strings.Builder, key, value string) {
	if value != "" {
		fmt.Fprintf(output, "\t\t%s = \"%s\"\n", key, value)
	}
}

func sanitizeRuleBase(value string) string {
	var output strings.Builder
	lastSeparator := false
	for _, r := range value {
		if isASCIIAlphaNumeric(r) {
			output.WriteRune(r)
			lastSeparator = false
		} else if !lastSeparator {
			output.WriteByte('_')
			lastSeparator = true
		}
	}
	return strings.TrimRight(output.String(), "_")
}

func sanitizeSignatureName(value string) string {
	var output strings.Builder
	lastSeparator := false
	for _, r := range value {
		if isASCIIAlphaNumeric(r) {
			output.WriteRune(r)
			lastSeparator = false
		} else if !lastSeparator {
			output.WriteByte('_')
			lastSeparator = true
		}
	}
	result := output.String()
	if strings.HasPrefix(result, "_") && len(result) > 1 {
		result = result[1:]
	}
	return result
}

func isASCIIAlphaNumeric(r rune) bool {
	return r <= unicode.MaxASCII && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
}

func formatCommentInstruction(instruction RuleInstruction) string {
	var output strings.Builder
	for _, value := range instruction.Instruction.Bytes {
		fmt.Fprintf(&output, "%02X ", value)
	}
	if missing := rawByteColumnWidth - len(instruction.Instruction.Bytes); missing > 0 {
		output.WriteString(strings.Repeat("   ", missing))
	}
	output.WriteString(instruction.Instruction.Assembly())
	return output.String()
}
