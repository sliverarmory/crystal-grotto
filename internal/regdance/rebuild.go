// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package regdance

import (
	"context"
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

func (p *dancePlan) finish(ctx context.Context) error {
	if err := p.relaxShortBranches(); err != nil {
		return err
	}
	starts, size, err := p.layout()
	if err != nil {
		return err
	}
	mapOffset := func(old uint32) (uint32, error) {
		if value, ok := starts[old]; ok {
			return value, nil
		}
		entry := instructionAt(p.instructions, old)
		if entry == nil {
			return 0, fmt.Errorf("offset %#x is outside .text", old)
		}
		if entry.rewritten || entry.expanded != branchUnchanged {
			return 0, fmt.Errorf("offset %#x points inside rewritten instruction %#x", old, entry.oldStart)
		}
		return starts[entry.oldStart] + old - entry.oldStart, nil
	}

	newSymbolValues, err := p.rebasedSymbols(mapOffset)
	if err != nil {
		return err
	}
	output := make([]byte, size)
	for _, entry := range p.instructions {
		copy(output[starts[entry.oldStart]:], entry.output)
	}
	if err := p.patchRelativeReferences(output, starts, mapOffset); err != nil {
		return err
	}
	newRelocationValues, err := p.rebasedRelocationAddresses(starts)
	if err != nil {
		return err
	}
	sectionData, err := p.rebasedRelocationAddends(output, newRelocationValues, newSymbolValues, mapOffset)
	if err != nil {
		return err
	}
	if err := p.validateExistingUnwind(starts, newRelocationValues); err != nil {
		return err
	}
	newAuxiliary, err := p.rebasedFunctionAuxiliary(mapOffset)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("regdance: %w", err)
	}

	// Commit the complete plan at once. Pointer identity of sections, symbols,
	// and relocations is retained for callers holding model references.
	for section, data := range sectionData {
		section.Data = data
		section.SizeOfRawData = uint32(len(data))
		if section == p.text && section.VirtualSize != 0 {
			section.VirtualSize = uint32(len(data))
		}
	}
	for relocation, value := range newRelocationValues {
		relocation.VirtualAddress = value
		if relocation.Section == nil {
			relocation.Section = p.text
		}
	}
	for symbol, value := range newSymbolValues {
		symbol.Value = value
	}
	for symbol, records := range newAuxiliary {
		symbol.AuxiliaryRecords = records
	}
	return nil
}

func (p *dancePlan) layout() (map[uint32]uint32, int, error) {
	starts := make(map[uint32]uint32, len(p.instructions)+1)
	var size uint64
	for _, entry := range p.instructions {
		starts[entry.oldStart] = uint32(size)
		size += uint64(len(entry.output))
		if size > math.MaxUint32 || size > uint64(math.MaxInt) {
			return nil, 0, errors.New("regdance: rewritten .text is too large")
		}
	}
	starts[uint32(len(p.text.Data))] = uint32(size)
	return starts, int(size), nil
}

func (p *dancePlan) relaxShortBranches() error {
	for iteration := 0; iteration <= len(p.instructions); iteration++ {
		starts, _, err := p.layout()
		if err != nil {
			return err
		}
		changed := false
		for _, entry := range p.instructions {
			if len(entry.relocations) != 0 || entry.expanded != branchUnchanged {
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
				return fmt.Errorf("regdance: short branch %#x targets outside .text", entry.oldStart)
			}
			newTarget, exists := starts[uint32(oldTarget)]
			if !exists {
				return fmt.Errorf("regdance: short branch %#x targets non-instruction boundary %#x", entry.oldStart, oldTarget)
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
				return fmt.Errorf("regdance: LOOP/JCXZ branch %#x overflows after register rewrite", entry.oldStart)
			default:
				return fmt.Errorf("regdance: unsupported short branch at %#x", entry.oldStart)
			}
			changed = true
		}
		if !changed {
			return nil
		}
	}
	return errors.New("regdance: branch relaxation did not converge")
}

func relativeTarget(entry *instruction, reference relativeReference) (int64, error) {
	if reference.offset < 0 || reference.size <= 0 || reference.offset+reference.size > len(entry.raw) {
		return 0, fmt.Errorf("regdance: malformed relative instruction at %#x", entry.oldStart)
	}
	var displacement int64
	if reference.size == 1 {
		displacement = int64(int8(entry.raw[reference.offset]))
	} else {
		displacement = int64(int32(binary.LittleEndian.Uint32(entry.raw[reference.offset : reference.offset+4])))
	}
	return int64(entry.oldEnd) + displacement, nil
}

func (p *dancePlan) patchRelativeReferences(output []byte, starts map[uint32]uint32, mapOffset func(uint32) (uint32, error)) error {
	for _, entry := range p.instructions {
		if len(entry.relocations) != 0 {
			continue
		}
		reference, relative := decodeRelative(entry.raw)
		if relative {
			if err := p.patchRelative(output, starts, mapOffset, entry, reference); err != nil {
				return err
			}
		} else if isDirectControlFlow(entry) {
			return fmt.Errorf("regdance: unsupported direct control-flow encoding at %#x", entry.oldStart)
		}
		if p.object.Machine == coff.MachineAMD64 && hasRegisterName(entry.operands, "rip") {
			if err := p.patchRIPRelative(output, starts, mapOffset, entry); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *dancePlan) patchRelative(output []byte, starts map[uint32]uint32, mapOffset func(uint32) (uint32, error), entry *instruction, reference relativeReference) error {
	oldTarget, err := relativeTarget(entry, reference)
	if err != nil {
		return err
	}
	newTarget := oldTarget
	if oldTarget >= 0 && oldTarget <= int64(len(p.text.Data)) {
		if _, boundary := p.boundaries[uint32(oldTarget)]; !boundary {
			return fmt.Errorf("regdance: branch %#x targets non-instruction boundary %#x", entry.oldStart, oldTarget)
		}
		if reference.kind == relativeCall && p.labels[uint32(oldTarget)] == nil {
			return fmt.Errorf("regdance: call %#x has no local symbol at %#x", entry.oldStart, oldTarget)
		}
		mapped, err := mapOffset(uint32(oldTarget))
		if err != nil {
			return fmt.Errorf("regdance: branch %#x: %w", entry.oldStart, err)
		}
		newTarget = int64(mapped)
	} else if reference.kind != relativeCall {
		return fmt.Errorf("regdance: branch %#x targets outside .text", entry.oldStart)
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
		return fmt.Errorf("regdance: relative field at %#x is out of bounds", entry.oldStart)
	}
	if fieldSize == 1 {
		if displacement < math.MinInt8 || displacement > math.MaxInt8 {
			return fmt.Errorf("regdance: short branch %#x still overflows after relaxation", entry.oldStart)
		}
		output[field] = byte(int8(displacement))
		return nil
	}
	if displacement < math.MinInt32 || displacement > math.MaxInt32 {
		return fmt.Errorf("regdance: rel32 at %#x overflows after register rewrite", entry.oldStart)
	}
	binary.LittleEndian.PutUint32(output[field:field+4], uint32(int32(displacement)))
	return nil
}

func (p *dancePlan) patchRIPRelative(output []byte, starts map[uint32]uint32, mapOffset func(uint32) (uint32, error), entry *instruction) error {
	oldEncoding, err := parseInstructionEncoding(entry.raw, coff.MachineAMD64)
	if err != nil || !isRIPRelative(oldEncoding) {
		return fmt.Errorf("regdance: unsupported RIP-relative encoding at %#x", entry.oldStart)
	}
	oldDisplacement := int64(int32(binary.LittleEndian.Uint32(entry.raw[oldEncoding.dispOffset:oldEncoding.tailOffset])))
	oldTarget := int64(entry.oldEnd) + oldDisplacement
	if oldTarget < 0 || oldTarget > int64(len(p.text.Data)) {
		return fmt.Errorf("regdance: RIP-relative instruction %#x targets outside .text without relocation", entry.oldStart)
	}
	if p.labels[uint32(oldTarget)] == nil {
		return fmt.Errorf("regdance: RIP-relative instruction %#x has no local symbol at %#x", entry.oldStart, oldTarget)
	}
	newTarget, err := mapOffset(uint32(oldTarget))
	if err != nil {
		return fmt.Errorf("regdance: RIP-relative instruction %#x: %w", entry.oldStart, err)
	}
	newEncoding, err := parseInstructionEncoding(entry.output, coff.MachineAMD64)
	if err != nil || !isRIPRelative(newEncoding) || newEncoding.dispSize != 4 {
		return fmt.Errorf("regdance: rewritten RIP-relative encoding at %#x is not provable", entry.oldStart)
	}
	start := starts[entry.oldStart]
	displacement := int64(newTarget) - int64(start+uint32(len(entry.output)))
	if displacement < math.MinInt32 || displacement > math.MaxInt32 {
		return fmt.Errorf("regdance: RIP-relative displacement at %#x overflows", entry.oldStart)
	}
	field := uint64(start) + uint64(newEncoding.dispOffset)
	if field+4 > uint64(len(output)) {
		return fmt.Errorf("regdance: RIP-relative field at %#x is out of bounds", entry.oldStart)
	}
	binary.LittleEndian.PutUint32(output[field:field+4], uint32(int32(displacement)))
	return nil
}

func isRIPRelative(encoding instructionEncoding) bool {
	return encoding.machine == coff.MachineAMD64 && !encoding.addressOverride && encoding.hasModRM && encoding.mod == 0 && !encoding.hasSIB && encoding.rm == 5 && encoding.dispSize == 4
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
	if _, ok := anyGPRName(operands); ok {
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

func (p *dancePlan) rebasedSymbols(mapOffset func(uint32) (uint32, error)) (map[*coff.Symbol]uint32, error) {
	textSymbols := make(map[*coff.Symbol]struct{})
	for _, symbol := range p.object.Symbols {
		if symbol.Section == p.text {
			textSymbols[symbol] = struct{}{}
		}
	}
	for _, section := range p.object.Sections {
		for _, relocation := range section.Relocations {
			if relocation.Symbol != nil && relocation.Symbol.Section == p.text {
				textSymbols[relocation.Symbol] = struct{}{}
			}
		}
	}
	values := make(map[*coff.Symbol]uint32, len(textSymbols))
	for symbol := range textSymbols {
		value, err := mapOffset(symbol.Value)
		if err != nil {
			return nil, fmt.Errorf("regdance: symbol %q: %w", symbol.Name, err)
		}
		values[symbol] = value
	}
	return values, nil
}

func (p *dancePlan) rebasedRelocationAddresses(starts map[uint32]uint32) (map[*coff.Relocation]uint32, error) {
	values := make(map[*coff.Relocation]uint32, len(p.text.Relocations))
	for _, entry := range p.instructions {
		start := starts[entry.oldStart]
		for _, relative := range entry.relocations {
			if relative.offset >= uint32(len(entry.output)) {
				return nil, fmt.Errorf("regdance: relocation offset escaped instruction %#x", entry.oldStart)
			}
			values[relative.relocation] = start + relative.offset
		}
	}
	return values, nil
}

func (p *dancePlan) rebasedRelocationAddends(textOutput []byte, relocationValues map[*coff.Relocation]uint32, symbolValues map[*coff.Symbol]uint32, mapOffset func(uint32) (uint32, error)) (map[*coff.Section][]byte, error) {
	sectionData := make(map[*coff.Section][]byte)
	sectionData[p.text] = textOutput
	for _, section := range p.object.Sections {
		for _, relocation := range section.Relocations {
			if relocation.Symbol == nil || relocation.Symbol.Section != p.text {
				continue
			}
			width, err := relocationWidth(p.object.Machine, relocation.Type)
			if err != nil {
				return nil, err
			}
			oldAddress := relocation.VirtualAddress
			newAddress := oldAddress
			if value, ok := relocationValues[relocation]; ok {
				newAddress = value
			}
			oldAddend, err := readSignedAddend(section.Data, oldAddress, width)
			if err != nil {
				return nil, fmt.Errorf("regdance: relocation %#x addend: %w", oldAddress, err)
			}
			oldTarget := int64(relocation.Symbol.Value) + oldAddend
			if oldTarget < 0 || oldTarget > int64(len(p.text.Data)) {
				continue
			}
			mappedTarget, err := mapOffset(uint32(oldTarget))
			if err != nil {
				return nil, fmt.Errorf("regdance: relocation %#x target: %w", oldAddress, err)
			}
			newSymbol, ok := symbolValues[relocation.Symbol]
			if !ok {
				return nil, fmt.Errorf("regdance: relocation %#x target symbol %q was not rebased", oldAddress, relocation.Symbol.Name)
			}
			newAddend := int64(mappedTarget) - int64(newSymbol)
			data := sectionData[section]
			if data == nil {
				data = append([]byte(nil), section.Data...)
				sectionData[section] = data
			}
			if err := writeSignedAddend(data, newAddress, width, newAddend); err != nil {
				return nil, fmt.Errorf("regdance: relocation %#x rebased addend: %w", oldAddress, err)
			}
		}
	}
	return sectionData, nil
}

func readSignedAddend(data []byte, address, width uint32) (int64, error) {
	if uint64(address)+uint64(width) > uint64(len(data)) {
		return 0, errors.New("field is out of bounds")
	}
	if width == 4 {
		return int64(int32(binary.LittleEndian.Uint32(data[address : address+4]))), nil
	}
	if width == 8 {
		return int64(binary.LittleEndian.Uint64(data[address : address+8])), nil
	}
	return 0, fmt.Errorf("unsupported addend width %d", width)
}

func writeSignedAddend(data []byte, address, width uint32, value int64) error {
	if uint64(address)+uint64(width) > uint64(len(data)) {
		return errors.New("field is out of bounds")
	}
	if width == 4 {
		if value < math.MinInt32 || value > math.MaxUint32 {
			return errors.New("addend does not fit 32 bits")
		}
		binary.LittleEndian.PutUint32(data[address:address+4], uint32(value))
		return nil
	}
	if width == 8 {
		binary.LittleEndian.PutUint64(data[address:address+8], uint64(value))
		return nil
	}
	return fmt.Errorf("unsupported addend width %d", width)
}

func (p *dancePlan) validateExistingUnwind(starts map[uint32]uint32, relocationValues map[*coff.Relocation]uint32) error {
	lengthChanged := false
	for _, entry := range p.instructions {
		if len(entry.output) != len(entry.raw) {
			lengthChanged = true
			break
		}
	}
	if !lengthChanged || p.object.Machine != coff.MachineAMD64 {
		return nil
	}
	for _, section := range p.object.Sections {
		if !strings.HasPrefix(section.Name, ".pdata") {
			continue
		}
		if len(section.Data)%12 != 0 {
			return &UnsupportedUnwindError{Reason: fmt.Sprintf("section %q is not a sequence of 12-byte RUNTIME_FUNCTION records", section.Name)}
		}
		for record := 0; record < len(section.Data); record += 12 {
			for _, field := range []uint32{uint32(record), uint32(record + 4)} {
				covered := false
				for _, relocation := range section.Relocations {
					if relocation.VirtualAddress == field && relocation.Symbol != nil && relocation.Symbol.Section == p.text {
						covered = true
						break
					}
				}
				if !covered {
					return &UnsupportedUnwindError{Offset: field, Reason: fmt.Sprintf("section %q runtime-function boundary lacks a .text relocation", section.Name)}
				}
			}
		}
	}
	_ = starts
	_ = relocationValues
	return nil
}

func (p *dancePlan) rebasedFunctionAuxiliary(mapOffset func(uint32) (uint32, error)) (map[*coff.Symbol][][]byte, error) {
	result := make(map[*coff.Symbol][][]byte)
	for _, symbol := range p.object.Symbols {
		if symbol.Section != p.text || !symbol.IsFunction() || len(symbol.AuxiliaryRecords) == 0 {
			continue
		}
		if len(symbol.AuxiliaryRecords[0]) != 18 {
			return nil, fmt.Errorf("regdance: function %q has malformed auxiliary record", symbol.Name)
		}
		var region *functionRegion
		for _, candidate := range p.functions {
			if candidate.start == symbol.Value && candidate.isFunction {
				region = candidate
				break
			}
		}
		if region == nil {
			continue
		}
		start, err := mapOffset(region.start)
		if err != nil {
			return nil, err
		}
		end, err := mapOffset(region.end)
		if err != nil {
			return nil, err
		}
		records := make([][]byte, len(symbol.AuxiliaryRecords))
		for index, record := range symbol.AuxiliaryRecords {
			records[index] = append([]byte(nil), record...)
		}
		binary.LittleEndian.PutUint32(records[0][4:8], end-start)
		result[symbol] = records
	}
	return result, nil
}
