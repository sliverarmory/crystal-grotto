// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package mutate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

type relativeKind uint8

const (
	relativeNone relativeKind = iota
	relativeCall
	relativeJump
	relativeConditional
	relativeLoop
)

type relativeReference struct {
	kind   relativeKind
	offset int
	size   int
}

func decodeRelative(raw []byte) (relativeReference, bool) {
	switch {
	case len(raw) == 5 && raw[0] == 0xe8:
		return relativeReference{kind: relativeCall, offset: 1, size: 4}, true
	case len(raw) == 5 && raw[0] == 0xe9:
		return relativeReference{kind: relativeJump, offset: 1, size: 4}, true
	case len(raw) == 2 && raw[0] == 0xeb:
		return relativeReference{kind: relativeJump, offset: 1, size: 1}, true
	case len(raw) == 2 && raw[0] >= 0x70 && raw[0] <= 0x7f:
		return relativeReference{kind: relativeConditional, offset: 1, size: 1}, true
	case len(raw) == 6 && raw[0] == 0x0f && raw[1] >= 0x80 && raw[1] <= 0x8f:
		return relativeReference{kind: relativeConditional, offset: 2, size: 4}, true
	case len(raw) == 2 && raw[0] >= 0xe0 && raw[0] <= 0xe3:
		return relativeReference{kind: relativeLoop, offset: 1, size: 1}, true
	default:
		return relativeReference{}, false
	}
}

func (p *mutationPlan) relaxShortBranches() error {
	for iteration := 0; iteration <= len(p.instructions); iteration++ {
		starts, _, err := p.layout()
		if err != nil {
			return err
		}
		changed := false
		for _, entry := range p.instructions {
			if len(entry.relocs) != 0 || entry.expanded != branchUnchanged {
				continue
			}
			reference, ok := decodeRelative(entry.raw)
			if !ok || reference.size != 1 {
				continue
			}
			oldTarget, err := relativeTarget(entry, reference)
			if err != nil {
				return err
			}
			if oldTarget < 0 || oldTarget > int64(len(p.text.Data)) {
				return fmt.Errorf("mutate: short branch %#x targets outside .text", entry.oldStart)
			}
			newTarget, exists := starts[uint32(oldTarget)]
			if !exists {
				return fmt.Errorf("mutate: short branch %#x targets non-instruction boundary %#x", entry.oldStart, oldTarget)
			}
			displacement := int64(newTarget) - int64(starts[entry.oldStart]+uint32(len(entry.output)))
			if displacement >= math.MinInt8 && displacement <= math.MaxInt8 {
				continue
			}
			switch reference.kind {
			case relativeJump:
				entry.output = []byte{0xe9, 0, 0, 0, 0}
				entry.expanded = branchNearJMP
			case relativeConditional:
				entry.output = []byte{0x0f, 0x80 | (entry.raw[0] & 0x0f), 0, 0, 0, 0}
				entry.expanded = branchNearJCC
			case relativeLoop:
				return fmt.Errorf("mutate: LOOP/JCXZ branch %#x overflows after mutation", entry.oldStart)
			default:
				return fmt.Errorf("mutate: unsupported short branch at %#x", entry.oldStart)
			}
			changed = true
		}
		if !changed {
			return nil
		}
	}
	return errors.New("mutate: branch relaxation did not converge")
}

func relativeTarget(entry *instruction, reference relativeReference) (int64, error) {
	if reference.offset < 0 || reference.size <= 0 || reference.offset+reference.size > len(entry.raw) {
		return 0, fmt.Errorf("mutate: malformed relative instruction at %#x", entry.oldStart)
	}
	var displacement int64
	if reference.size == 1 {
		displacement = int64(int8(entry.raw[reference.offset]))
	} else {
		displacement = int64(int32(binary.LittleEndian.Uint32(entry.raw[reference.offset : reference.offset+4])))
	}
	return int64(entry.oldEnd) + displacement, nil
}

func (p *mutationPlan) patchRelativeReferences(output []byte, starts map[uint32]uint32, mapOffset func(uint32) (uint32, error)) error {
	for _, entry := range p.instructions {
		if len(entry.relocs) != 0 {
			continue
		}
		reference, relative := decodeRelative(entry.raw)
		if relative {
			if err := p.patchRelative(output, starts, mapOffset, entry, reference); err != nil {
				return err
			}
		} else if isDirectControlFlow(entry) {
			return fmt.Errorf("mutate: unsupported direct control-flow encoding at %#x", entry.oldStart)
		}
		if p.object.Machine == coff.MachineAMD64 && strings.Contains(entry.operands, "rip") {
			if err := p.patchRIPRelative(output, starts, mapOffset, entry); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *mutationPlan) patchRelative(output []byte, starts map[uint32]uint32, mapOffset func(uint32) (uint32, error), entry *instruction, reference relativeReference) error {
	oldTarget, err := relativeTarget(entry, reference)
	if err != nil {
		return err
	}
	newTarget := oldTarget
	if oldTarget >= 0 && oldTarget <= int64(len(p.text.Data)) {
		mapped, err := mapOffset(uint32(oldTarget))
		if err != nil {
			return fmt.Errorf("mutate: branch %#x: %w", entry.oldStart, err)
		}
		if _, boundary := p.boundaries[uint32(oldTarget)]; !boundary {
			return fmt.Errorf("mutate: branch %#x targets non-instruction boundary %#x", entry.oldStart, oldTarget)
		}
		newTarget = int64(mapped)
	} else if reference.kind != relativeCall {
		return fmt.Errorf("mutate: branch %#x targets outside .text", entry.oldStart)
	}
	start := starts[entry.oldStart]
	end := int64(start) + int64(len(entry.output))
	displacement := newTarget - end
	fieldOffset, fieldSize := reference.offset, reference.size
	switch entry.expanded {
	case branchNearJMP:
		fieldOffset, fieldSize = 1, 4
	case branchNearJCC:
		fieldOffset, fieldSize = 2, 4
	}
	field := uint64(start) + uint64(fieldOffset)
	if field+uint64(fieldSize) > uint64(len(output)) {
		return fmt.Errorf("mutate: relative field at %#x is out of bounds", entry.oldStart)
	}
	if fieldSize == 1 {
		if displacement < math.MinInt8 || displacement > math.MaxInt8 {
			return fmt.Errorf("mutate: short branch %#x still overflows after relaxation", entry.oldStart)
		}
		output[field] = byte(int8(displacement))
		return nil
	}
	if displacement < math.MinInt32 || displacement > math.MaxInt32 {
		return fmt.Errorf("mutate: rel32 at %#x overflows after mutation", entry.oldStart)
	}
	binary.LittleEndian.PutUint32(output[field:field+4], uint32(int32(displacement)))
	return nil
}

func (p *mutationPlan) patchRIPRelative(output []byte, starts map[uint32]uint32, mapOffset func(uint32) (uint32, error), entry *instruction) error {
	if entry.mutated || entry.expanded != branchUnchanged {
		return fmt.Errorf("mutate: rewritten instruction %#x unexpectedly uses RIP-relative memory", entry.oldStart)
	}
	fieldOffset, ok := ripDisplacementOffset(entry.raw)
	if !ok {
		return fmt.Errorf("mutate: unsupported RIP-relative encoding at %#x", entry.oldStart)
	}
	oldDisplacement := int64(int32(binary.LittleEndian.Uint32(entry.raw[fieldOffset : fieldOffset+4])))
	oldTarget := int64(entry.oldEnd) + oldDisplacement
	newTarget := oldTarget
	if oldTarget >= 0 && oldTarget <= int64(len(p.text.Data)) {
		mapped, err := mapOffset(uint32(oldTarget))
		if err != nil {
			return fmt.Errorf("mutate: RIP-relative instruction %#x: %w", entry.oldStart, err)
		}
		newTarget = int64(mapped)
	}
	start := starts[entry.oldStart]
	displacement := newTarget - int64(start+uint32(len(entry.output)))
	if displacement < math.MinInt32 || displacement > math.MaxInt32 {
		return fmt.Errorf("mutate: RIP-relative displacement at %#x overflows", entry.oldStart)
	}
	field := uint64(start) + uint64(fieldOffset)
	if field+4 > uint64(len(output)) {
		return fmt.Errorf("mutate: RIP-relative field at %#x is out of bounds", entry.oldStart)
	}
	binary.LittleEndian.PutUint32(output[field:field+4], uint32(int32(displacement)))
	return nil
}

func ripDisplacementOffset(raw []byte) (int, bool) {
	prefix, err := parsePrefixes(raw, true)
	if err != nil || prefix.address32 || prefix.opcodeOffset >= len(raw) {
		return 0, false
	}
	index := prefix.opcodeOffset
	opcode := raw[index]
	index++
	switch opcode {
	case 0x8a, 0x8b, 0x88, 0x89, 0x8d, 0x38, 0x39, 0x3a, 0x3b, 0x84, 0x85,
		0x80, 0x81, 0x83, 0xc6, 0xc7, 0xf6, 0xf7, 0xfe, 0xff:
	case 0x0f:
		if index >= len(raw) {
			return 0, false
		}
		second := raw[index]
		index++
		if second != 0xb6 && second != 0xb7 && second != 0xbe && second != 0xbf {
			return 0, false
		}
	default:
		return 0, false
	}
	if index >= len(raw) {
		return 0, false
	}
	modRM := raw[index]
	if modRM>>6 != 0 || modRM&7 != 5 {
		return 0, false
	}
	index++
	if index+4 > len(raw) {
		return 0, false
	}
	return index, true
}

func isDirectControlFlow(entry *instruction) bool {
	if entry == nil {
		return false
	}
	mnemonic := entry.mnemonic
	if mnemonic != "call" && mnemonic != "jmp" && !strings.HasPrefix(mnemonic, "j") && !strings.HasPrefix(mnemonic, "loop") {
		return false
	}
	operands := strings.TrimSpace(entry.operands)
	if operands == "" || strings.ContainsAny(operands, "[]") {
		return false
	}
	numeric := strings.TrimPrefix(strings.TrimPrefix(operands, "+"), "-")
	numeric = strings.TrimPrefix(numeric, "0x")
	if numeric == "" {
		return false
	}
	for _, character := range numeric {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
