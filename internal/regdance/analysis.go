// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package regdance

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

type savedContext struct {
	prologue         map[*instruction]struct{}
	epilogue         map[*instruction]struct{}
	exclude          map[Register]struct{}
	swappable        []Register
	framePointer     *instruction
	prologueBoundary uint32
}

func analyzeSavedRegisters(plan *dancePlan, function *functionRegion) (*savedContext, error) {
	context := &savedContext{
		prologue: make(map[*instruction]struct{}),
		epilogue: make(map[*instruction]struct{}),
		exclude:  make(map[Register]struct{}),
	}
	instructions := function.instructions
	position := 0
	for position < len(instructions) {
		next := instructions[position]
		position++
		if isNativePush(next, plan.object.Machine) {
			context.prologue[next] = struct{}{}
			continue
		}
		if plan.object.Machine == coff.MachineAMD64 && isStackAdjustment(next, "sub") {
			continue
		}
		if plan.object.Machine == coff.MachineAMD64 && (isFrameMOV(next) || isFrameLEA(next, plan.object.Machine)) {
			context.framePointer = next
			context.prologueBoundary = next.oldEnd
			break
		}
		context.prologueBoundary = next.oldStart
		break
	}
	if context.prologueBoundary == 0 && len(instructions) > 0 {
		context.prologueBoundary = instructions[minInt(position, len(instructions))-1].oldEnd
	}

	exitIndex := -1
	for index := position; index < len(instructions); index++ {
		if isWalkerExit(instructions[index], plan.object.Machine) {
			exitIndex = index
			break
		}
	}
	if exitIndex >= 0 {
		for index := exitIndex - 1; index >= 0; index-- {
			previous := instructions[index]
			if isNativePop(previous, plan.object.Machine) {
				context.epilogue[previous] = struct{}{}
				continue
			}
			if plan.object.Machine == coff.MachineAMD64 && isStackAdjustment(previous, "add") {
				continue
			}
			break
		}
	}

	for _, next := range instructions {
		uses := explicitRegisterUses(next.operands)
		if isStringInstruction(next.mnemonic) {
			context.exclude[RSI] = struct{}{}
			context.exclude[RDI] = struct{}{}
		} else if isRBXImplicit(next.mnemonic) {
			context.exclude[RBX] = struct{}{}
		} else if hasRegisterName(next.operands, "bh") {
			context.exclude[RBX] = struct{}{}
		} else if plan.object.Machine == coff.MachineI386 && hasRegisterName(next.operands, "bl") {
			context.exclude[RBX] = struct{}{}
		} else if excludesFramePointer(next.mnemonic) {
			context.exclude[RBP] = struct{}{}
		}
		if len(next.relocations) != 0 {
			for _, use := range uses {
				context.exclude[use.base] = struct{}{}
			}
		}
		if usesAnyHighByte(next.operands) {
			for _, use := range uses {
				context.exclude[use.base] = struct{}{}
			}
		}
	}

	set := make(map[Register]struct{})
	native := nativeRegisters(plan.object.Machine)
	for next := range context.prologue {
		uses := explicitRegisterUses(next.operands)
		if len(uses) == 1 {
			if _, ok := native[uses[0].base]; ok {
				set[uses[0].base] = struct{}{}
			}
		}
	}
	for excluded := range context.exclude {
		delete(set, excluded)
	}
	context.swappable = orderedRegisters(set)
	return context, nil
}

func (c *savedContext) sane() bool {
	return len(c.prologue) > 0 && len(c.prologue) == len(c.epilogue) && len(c.swappable) >= 3
}

func (c *savedContext) isBookend(entry *instruction) bool {
	_, prologue := c.prologue[entry]
	_, epilogue := c.epilogue[entry]
	return prologue || epilogue
}

func exitCount(plan *dancePlan, function *functionRegion) (int, error) {
	count := 0
	for _, next := range function.instructions {
		if isWalkerExit(next, plan.object.Machine) {
			count++
			continue
		}
		if isIndirectNativeJump(next, plan.object.Machine) && len(next.relocations) != 0 {
			count++
			continue
		}
		if target, ok, err := directJumpTarget(next); err != nil {
			return 0, err
		} else if ok {
			if _, label := plan.labels[uint32(target)]; target >= 0 && target <= int64(^uint32(0)) && label {
				count++
			}
		}
	}
	return count, nil
}

func isNativePush(entry *instruction, machine coff.Machine) bool {
	if entry.mnemonic != "push" || strings.Contains(entry.operands, "[") {
		return false
	}
	uses := allGPRUses(entry.operands)
	want := 32
	if machine == coff.MachineAMD64 {
		want = 64
	}
	return len(uses) == 1 && uses[0].size == want
}

func isNativePop(entry *instruction, machine coff.Machine) bool {
	if entry.mnemonic != "pop" || strings.Contains(entry.operands, "[") {
		return false
	}
	uses := allGPRUses(entry.operands)
	want := 32
	if machine == coff.MachineAMD64 {
		want = 64
	}
	return len(uses) == 1 && uses[0].size == want
}

func allGPRUses(operands string) []registerUse {
	var result []registerUse
	for _, word := range words(operands) {
		if use, ok := anyGPRName(word); ok {
			result = append(result, use)
		}
	}
	return result
}

func anyGPRName(name string) (registerUse, bool) {
	if use, ok := registerNames[name]; ok {
		return use, true
	}
	legacy := map[string]registerUse{
		"rax": {0, 64, false}, "eax": {0, 32, false}, "ax": {0, 16, false}, "al": {0, 8, false}, "ah": {0, 8, true},
		"rcx": {1, 64, false}, "ecx": {1, 32, false}, "cx": {1, 16, false}, "cl": {1, 8, false}, "ch": {1, 8, true},
		"rdx": {2, 64, false}, "edx": {2, 32, false}, "dx": {2, 16, false}, "dl": {2, 8, false}, "dh": {2, 8, true},
		"rsp": {4, 64, false}, "esp": {4, 32, false}, "sp": {4, 16, false}, "spl": {4, 8, false},
	}
	if use, ok := legacy[name]; ok {
		return use, true
	}
	if len(name) >= 2 && name[0] == 'r' && name[1] >= '8' && name[1] <= '9' || len(name) >= 3 && name[0] == 'r' && name[1] == '1' && name[2] >= '0' && name[2] <= '5' {
		numberEnd := 1
		for numberEnd < len(name) && name[numberEnd] >= '0' && name[numberEnd] <= '9' {
			numberEnd++
		}
		var number int
		for _, digit := range name[1:numberEnd] {
			number = number*10 + int(digit-'0')
		}
		size := 64
		switch name[numberEnd:] {
		case "d":
			size = 32
		case "w":
			size = 16
		case "b":
			size = 8
		case "":
		default:
			return registerUse{}, false
		}
		return registerUse{base: Register(number), size: size}, true
	}
	return registerUse{}, false
}

func isStackAdjustment(entry *instruction, mnemonic string) bool {
	if entry.mnemonic != mnemonic {
		return false
	}
	operands := splitOperands(entry.operands)
	return len(operands) == 2 && operands[0] == "rsp" && !strings.Contains(operands[1], "[")
}

func isFrameMOV(entry *instruction) bool {
	if entry.mnemonic != "mov" {
		return false
	}
	operands := splitOperands(entry.operands)
	if len(operands) != 2 || operands[1] != "rsp" {
		return false
	}
	encoding, err := parseInstructionEncoding(entry.raw, coff.MachineAMD64)
	return err == nil && len(encoding.opcode) == 1 && encoding.opcode[0] == 0x89 && encoding.rex&8 != 0
}

func isFrameLEA(entry *instruction, machine coff.Machine) bool {
	if entry.mnemonic != "lea" || machine != coff.MachineAMD64 {
		return false
	}
	encoding, err := parseInstructionEncoding(entry.raw, machine)
	if err != nil || len(encoding.opcode) != 1 || encoding.opcode[0] != 0x8d || encoding.rex&8 == 0 {
		return false
	}
	base, present := encoding.memoryBase()
	return present && base == 4
}

func isWalkerExit(entry *instruction, machine coff.Machine) bool {
	if isPlainRET(entry) {
		return true
	}
	return machine == coff.MachineAMD64 && entry.mnemonic == "jmp" && normalizeOperands(entry.operands) == "rcx"
}

func isPlainRET(entry *instruction) bool {
	position := 0
	for position < len(entry.raw) && isLegacyPrefix(entry.raw[position]) {
		position++
	}
	return entry.mnemonic == "ret" && position+1 == len(entry.raw) && entry.raw[position] == 0xc3
}

func isIndirectNativeJump(entry *instruction, machine coff.Machine) bool {
	if entry.mnemonic != "jmp" {
		return false
	}
	encoding, err := parseInstructionEncoding(entry.raw, machine)
	return err == nil && len(encoding.opcode) == 1 && encoding.opcode[0] == 0xff && encoding.hasModRM && encoding.reg == 4
}

func directJumpTarget(entry *instruction) (int64, bool, error) {
	raw := entry.raw
	if len(raw) == 2 && raw[0] == 0xeb {
		return int64(entry.oldEnd) + int64(int8(raw[1])), true, nil
	}
	if len(raw) == 5 && raw[0] == 0xe9 {
		return int64(entry.oldEnd) + int64(int32(binary.LittleEndian.Uint32(raw[1:]))), true, nil
	}
	if entry.mnemonic == "jmp" && !strings.Contains(entry.operands, "[") && !isIndirectNativeJump(entry, coff.MachineAMD64) && !isIndirectNativeJump(entry, coff.MachineI386) {
		return 0, false, fmt.Errorf("regdance: unsupported direct jump encoding at %#x", entry.oldStart)
	}
	return 0, false, nil
}

func isStringInstruction(mnemonic string) bool {
	parts := strings.Fields(strings.ToLower(mnemonic))
	if len(parts) == 0 {
		return false
	}
	name := parts[len(parts)-1]
	for _, prefix := range []string{"movs", "cmps", "scas", "lods", "stos", "ins", "outs"} {
		if name == prefix || strings.HasPrefix(name, prefix) && len(name) == len(prefix)+1 {
			return true
		}
	}
	return false
}

func isRBXImplicit(mnemonic string) bool {
	name := lastMnemonicWord(mnemonic)
	return name == "cpuid" || name == "cmpxchg16b" || name == "xlat" || name == "xlatb" || name == "cmpxchg8b"
}

func excludesFramePointer(mnemonic string) bool {
	switch lastMnemonicWord(mnemonic) {
	case "leave", "enter", "pusha", "popa", "pushad", "popad", "pushal", "popal":
		return true
	default:
		return false
	}
}

func usesAnyHighByte(operands string) bool {
	return hasRegisterName(operands, "ah") || hasRegisterName(operands, "ch") || hasRegisterName(operands, "dh") || hasRegisterName(operands, "bh")
}

func lastMnemonicWord(value string) string {
	parts := strings.Fields(strings.ToLower(value))
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func splitOperands(value string) []string {
	var result []string
	start, depth := 0, 0
	for index, character := range value {
		switch character {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				result = append(result, strings.TrimSpace(strings.ToLower(value[start:index])))
				start = index + 1
			}
		}
	}
	result = append(result, strings.TrimSpace(strings.ToLower(value[start:])))
	return result
}

func sortedFunctionRegions(regions []*functionRegion) {
	sort.Slice(regions, func(i, j int) bool {
		if regions[i].start != regions[j].start {
			return regions[i].start < regions[j].start
		}
		return regions[i].name < regions[j].name
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
