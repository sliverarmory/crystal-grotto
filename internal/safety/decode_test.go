// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package safety

import (
	"math"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestDecodeDirectControlFlow(t *testing.T) {
	tests := []struct {
		name        string
		mode        x86.Mode
		instruction x86.Instruction
		flow        controlFlow
		target      uint64
		wantError   string
	}{
		{name: "call rel32", mode: x86.Mode64, instruction: insn(10, "call", "", 0xe8, 1, 0, 0, 0), flow: flowCall, target: 16},
		{name: "jmp rel32 negative", mode: x86.Mode32, instruction: insn(10, "jmp", "", 0xe9, 0xf1, 0xff, 0xff, 0xff), flow: flowJump, target: 0},
		{name: "jmp rel8", mode: x86.Mode64, instruction: insn(4, "jmp", "", 0xeb, 2), flow: flowJump, target: 8},
		{name: "x86 rel16 prefixes", mode: x86.Mode32, instruction: insn(0, "call", "", 0xf3, 0x66, 0xe8, 1, 0), flow: flowCall, target: 6},
		{name: "x64 rejects rel16", mode: x86.Mode64, instruction: insn(0, "call", "", 0x66, 0xe8, 1, 0), wantError: "16-bit displacement"},
		{name: "call mnemonic mismatch", mode: x86.Mode64, instruction: insn(0, "jmp", "", 0xe8, 0, 0, 0, 0), wantError: "want call"},
		{name: "jmp mnemonic mismatch", mode: x86.Mode64, instruction: insn(0, "call", "", 0xe9, 0, 0, 0, 0), wantError: "want jmp"},
		{name: "short mismatch", mode: x86.Mode64, instruction: insn(0, "call", "", 0xeb, 0), wantError: "want jmp"},
		{name: "bad rel32 size", mode: x86.Mode64, instruction: insn(0, "call", "", 0xe8, 0), wantError: "displacement is 1 bytes"},
		{name: "bad rel8 size", mode: x86.Mode64, instruction: insn(0, "jmp", "", 0xeb, 0, 0), wantError: "displacement is 2 bytes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeSemantics(test.instruction, test.mode)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.flow != test.flow || !got.direct || got.directTarget != test.target {
				t.Fatalf("semantics = %#v", got)
			}
		})
	}
}

func TestDecodeIndirectAndRIPRelativeForms(t *testing.T) {
	tests := []struct {
		name        string
		mode        x86.Mode
		instruction x86.Instruction
		flow        controlFlow
		rip         bool
		target      uint64
		wantError   string
	}{
		{name: "register call", mode: x86.Mode64, instruction: insn(0, "call", "rax", 0xff, 0xd0), flow: flowCall},
		{name: "RIP call", mode: x86.Mode64, instruction: insn(0, "call", "qword ptr [rip + 2]", 0xff, 0x15, 2, 0, 0, 0), flow: flowCall, rip: true, target: 8},
		{name: "RIP jmp with REX", mode: x86.Mode64, instruction: insn(0, "jmp", "qword ptr [rip + 1]", 0x40, 0xff, 0x25, 1, 0, 0, 0), flow: flowJump, rip: true, target: 8},
		{name: "address override is not RIP", mode: x86.Mode64, instruction: insn(0, "call", "qword ptr [eip]", 0x67, 0xff, 0x15, 0, 0, 0, 0), flow: flowCall},
		{name: "truncated FF", mode: x86.Mode64, instruction: insn(0, "call", "", 0xff), wantError: "truncated"},
		{name: "FF wrong mnemonic", mode: x86.Mode64, instruction: insn(0, "jmp", "", 0xff, 0xd0), wantError: "want call"},
		{name: "far FF call", mode: x86.Mode64, instruction: insn(0, "call", "", 0xff, 0xd8), wantError: "unsupported FF /3"},
		{name: "non-control FF", mode: x86.Mode64, instruction: insn(0, "inc", "eax", 0xff, 0xc0)},
		{name: "generic unsupported call", mode: x86.Mode32, instruction: insn(0, "call", "far", 0x9a, 0, 0, 0, 0, 0, 0), flow: flowCall},
		{name: "RIP lea", mode: x86.Mode64, instruction: insn(0, "lea", "rax, [rip + 1]", 0x48, 0x8d, 0x05, 1, 0, 0, 0), rip: true, target: 8},
		{name: "RIP mov", mode: x86.Mode64, instruction: insn(0, "mov", "rax, [rip + 1]", 0x48, 0x8b, 0x05, 1, 0, 0, 0), rip: true, target: 8},
		{name: "mov lacks REX.W", mode: x86.Mode64, instruction: insn(0, "mov", "eax, [rip + 1]", 0x8b, 0x05, 1, 0, 0, 0), wantError: "unsupported encoding"},
		{name: "lea operand mismatch", mode: x86.Mode64, instruction: insn(0, "lea", "rax, [rip]", 0x48, 0x8d, 0x00), wantError: "without RIP-relative ModRM"},
		{name: "lea truncated displacement", mode: x86.Mode64, instruction: insn(0, "lea", "rax, [rip]", 0x48, 0x8d, 0x05, 0), wantError: "unsupported encoding"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeSemantics(test.instruction, test.mode)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.flow != test.flow || got.ripReference != test.rip || got.ripTarget != test.target {
				t.Fatalf("semantics = %#v", got)
			}
			if test.flow != flowNone && !got.indirect {
				t.Fatalf("control flow is not indirect: %#v", got)
			}
		})
	}
}

func TestDecodeValidationAndRelativeBounds(t *testing.T) {
	if _, err := decodeSemantics(x86.Instruction{}, x86.Mode64); err == nil || !strings.Contains(err.Error(), "no bytes") {
		t.Fatalf("empty error = %v", err)
	}
	if _, err := decodeSemantics(insn(0, "nop", "", 0x66), x86.Mode64); err == nil || !strings.Contains(err.Error(), "only of prefixes") {
		t.Fatalf("prefix error = %v", err)
	}
	if _, _, override := opcodeOffset([]byte{0xf0, 0x67, 0x48, 0x90}, x86.Mode64); !override {
		t.Fatal("address override not detected")
	}
	if offset, rexW, _ := opcodeOffset([]byte{0x66, 0x48, 0x90}, x86.Mode64); offset != 2 || !rexW {
		t.Fatalf("opcodeOffset = %d, %v", offset, rexW)
	}
	if _, ok, err := ripRelativeTarget(insn(0, "lea", "", 0x48, 0x8d, 0x05), 3); err != nil || ok {
		t.Fatalf("ripRelativeTarget = ok %v, err %v", ok, err)
	}
	if _, err := addRelative(0, 1, -2); err == nil || !strings.Contains(err.Error(), "precedes") {
		t.Fatalf("underflow error = %v", err)
	}
	if _, err := addRelative(math.MaxUint64-1, 2, 0); err == nil || !strings.Contains(err.Error(), "end address") {
		t.Fatalf("end overflow error = %v", err)
	}
	if _, err := addRelative(math.MaxUint64-2, 1, 2); err == nil || !strings.Contains(err.Error(), "target overflows") {
		t.Fatalf("target overflow error = %v", err)
	}
}

func insn(address uint64, mnemonic, operands string, raw ...byte) x86.Instruction {
	return x86.Instruction{Address: address, Bytes: append([]byte(nil), raw...), Mnemonic: mnemonic, Operands: operands}
}
