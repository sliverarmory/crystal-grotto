// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package mutate

import (
	"fmt"
	"strings"
)

// flagsLiveAfter mirrors the part of Crystal Palace Zones analysis needed by
// Mutator. A neutral candidate is dangerous when a later instruction consumes
// the current flags before a definite writer or volatile call boundary. With
// no Iced RFLAGS metadata, unfamiliar instructions and control-flow crossings
// are rejected instead of guessed.
func flagsLiveAfter(instructions []*instruction, current int, regions []functionRegion) (bool, error) {
	entry := instructions[current]
	limit := regionEnd(regions, entry.oldStart, instructions[len(instructions)-1].oldEnd)
	for index := current + 1; index < len(instructions) && instructions[index].oldStart < limit; index++ {
		next := instructions[index]
		mnemonic := strings.ToLower(next.mnemonic)
		if readsFlags(mnemonic) {
			return true, nil
		}
		if writesFlags(mnemonic) || mnemonic == "call" || mnemonic == "ret" || mnemonic == "int" || mnemonic == "syscall" || mnemonic == "ud2" {
			return false, nil
		}
		if mnemonic == "jmp" || strings.HasPrefix(mnemonic, "loop") {
			return false, fmt.Errorf("cannot prove flags liveness across %s at %#x", mnemonic, next.oldStart)
		}
		if !neutralForFlags(mnemonic) {
			return false, fmt.Errorf("cannot prove RFLAGS behavior of %s at %#x", mnemonic, next.oldStart)
		}
	}
	return false, nil
}

func readsFlags(mnemonic string) bool {
	return (strings.HasPrefix(mnemonic, "j") && mnemonic != "jmp") ||
		strings.HasPrefix(mnemonic, "cmov") ||
		strings.HasPrefix(mnemonic, "set") ||
		mnemonic == "adc" || mnemonic == "sbb" ||
		mnemonic == "lahf" || mnemonic == "pushf" || mnemonic == "pushfd" || mnemonic == "pushfq" ||
		strings.HasPrefix(mnemonic, "loop")
}

func writesFlags(mnemonic string) bool {
	switch mnemonic {
	case "add", "sub", "cmp", "test", "and", "or", "xor", "inc", "dec", "neg",
		"mul", "imul", "div", "idiv", "shl", "shr", "sar", "sal", "rol", "ror",
		"rcl", "rcr", "bt", "btc", "btr", "bts", "xadd", "cmpxchg", "popf", "popfd", "popfq",
		"sahf", "clc", "stc", "cmc", "cld", "std":
		return true
	default:
		return false
	}
}

func neutralForFlags(mnemonic string) bool {
	switch mnemonic {
	case "mov", "movabs", "movzx", "movsx", "movsxd", "lea", "push", "pop", "nop", "xchg",
		"leave", "endbr32", "endbr64", "cdqe", "cwde", "cdq", "cqo", "bswap", "not":
		return true
	default:
		return false
	}
}
