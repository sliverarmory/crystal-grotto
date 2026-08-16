// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.
// See LICENSE.upstream.

package x86

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	upstreamRawByteWidth = 10
	upstreamFormColumn   = 40
)

// FormatInstruction returns the stable subset of Crystal Palace's default
// CodeFormat layout: a 16-digit uppercase address, concatenated uppercase raw
// bytes padded to a ten-byte column, and Intel-syntax assembly. If showForm is
// true and Form is non-empty, the canonical form is appended in the upstream
// 40-character comment column. The Capstone v0.0.1 backend leaves Form empty.
func FormatInstruction(instruction Instruction, showForm bool) string {
	var output strings.Builder
	fmt.Fprintf(&output, "%016X ", instruction.Address)

	raw := strings.ToUpper(hex.EncodeToString(instruction.Bytes))
	output.WriteString(raw)
	if missing := upstreamRawByteWidth - len(instruction.Bytes); missing > 0 {
		output.WriteString(strings.Repeat("  ", missing))
	}
	output.WriteByte(' ')

	assembly := instruction.Assembly()
	output.WriteString(assembly)
	if showForm && instruction.Form != "" {
		if padding := upstreamFormColumn - len(assembly); padding > 0 {
			output.WriteString(strings.Repeat(" ", padding))
		}
		output.WriteString("; ")
		output.WriteString(instruction.Form)
	}
	return output.String()
}

// Format returns one formatted instruction per line. Empty input returns an
// empty string; non-empty output has a trailing newline like Crystal Palace's
// PrintStream-based formatter.
func Format(instructions []Instruction, showForms bool) string {
	var output strings.Builder
	for _, instruction := range instructions {
		output.WriteString(FormatInstruction(instruction, showForms))
		output.WriteByte('\n')
	}
	return output.String()
}
