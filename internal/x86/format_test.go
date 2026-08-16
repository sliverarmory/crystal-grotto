// SPDX-License-Identifier: GPL-3.0-only

package x86

import "testing"

func TestFormatInstruction(t *testing.T) {
	tests := []struct {
		name      string
		input     Instruction
		showForms bool
		want      string
	}{
		{
			name:  "default upstream columns",
			input: Instruction{Address: 0x401000, Bytes: []byte{0x48, 0x89, 0xe5}, Mnemonic: "mov", Operands: "rbp, rsp"},
			want:  "0000000000401000 4889E5               mov rbp, rsp",
		},
		{
			name:      "available form",
			input:     Instruction{Address: 0x10, Bytes: []byte{0xe8, 0, 0, 0, 0}, Mnemonic: "call", Operands: "0x15", Form: "CALL rel32"},
			showForms: true,
			want:      "0000000000000010 E800000000           call 0x15                               ; CALL rel32",
		},
		{
			name:      "unavailable form is not invented",
			input:     Instruction{Address: 0, Bytes: []byte{0xc3}, Mnemonic: "ret"},
			showForms: true,
			want:      "0000000000000000 C3                   ret",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := FormatInstruction(test.input, test.showForms); got != test.want {
				t.Fatalf("FormatInstruction() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	if got := Format(nil, false); got != "" {
		t.Fatalf("Format(nil) = %q, want empty", got)
	}
	instructions := []Instruction{
		{Address: 0, Bytes: []byte{0x90}, Mnemonic: "nop"},
		{Address: 1, Bytes: []byte{0xc3}, Mnemonic: "ret"},
	}
	want := "0000000000000000 90                   nop\n" +
		"0000000000000001 C3                   ret\n"
	if got := Format(instructions, false); got != want {
		t.Fatalf("Format() = %q, want %q", got, want)
	}
}
