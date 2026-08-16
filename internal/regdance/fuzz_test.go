// SPDX-License-Identifier: GPL-3.0-only

package regdance

import (
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func FuzzParseInstructionEncoding(f *testing.F) {
	f.Add([]byte{0x4a, 0x8d, 0x74, 0x63, 0x10}, true)
	f.Add([]byte{0x8d, 0x74, 0x5d, 0x10}, false)
	f.Add([]byte{0xc5, 0xfc, 0x10, 0x03}, true)
	f.Fuzz(func(t *testing.T, raw []byte, mode64 bool) {
		machine := coff.MachineI386
		if mode64 {
			machine = coff.MachineAMD64
		}
		encoding, err := parseInstructionEncoding(raw, machine)
		if err != nil {
			return
		}
		mapping := map[Register]Register{RBP: RBX, RBX: R12, RSI: R13, RDI: RSI, R12: RBP, R13: RDI}
		fields := encoding.candidateFields(mapping)
		if len(fields) > 8 {
			return
		}
		for selected := uint(0); selected < 1<<len(fields); selected++ {
			_, _ = encoding.rewrite(fields, selected, mapping, "rbx")
		}
	})
}

func FuzzRegisterReplacement(f *testing.F) {
	f.Add("r13, qword ptr [rbp + rbx*2 + 0x10]")
	f.Add("byte ptr [rsi], bl")
	f.Fuzz(func(t *testing.T, operands string) {
		mapping := map[Register]Register{RBP: RBX, RBX: R12, RSI: R13, RDI: RSI, R12: RBP, R13: RDI}
		replaced, _ := replaceRegisters(operands, mapping)
		_, _ = replaceRegisters(replaced, mapping)
	})
}
