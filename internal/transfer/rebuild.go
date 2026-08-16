// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package transfer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func (p *plan) finish(ctx context.Context) error {
	if err := p.relaxBranches(ctx); err != nil {
		return err
	}
	starts, total, err := p.layout()
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
		encoded := p.encodedInstruction(entry)
		if entry.removed || entry.replacement != nil || len(encoded) != len(entry.raw) {
			return 0, fmt.Errorf("offset %#x points inside rewritten instruction %#x", old, entry.oldStart)
		}
		return starts[entry.oldStart] + old - entry.oldStart, nil
	}

	symbolValues, err := p.rebasedSymbols(mapOffset)
	if err != nil {
		return err
	}
	output := make([]byte, total)
	for _, entry := range p.instructions {
		copy(output[starts[entry.oldStart]:], p.encodedInstruction(entry))
	}
	if err := p.patchControlFlow(output, starts, mapOffset); err != nil {
		return err
	}
	relocationValues, err := p.rebasedRelocationAddresses(starts)
	if err != nil {
		return err
	}
	sectionData, err := p.rebasedRelocationAddends(output, relocationValues, symbolValues, mapOffset)
	if err != nil {
		return err
	}
	if err := p.validateExistingUnwind(p.codeLayoutChanged(starts, total)); err != nil {
		return err
	}
	auxiliary, err := p.rebasedFunctionAuxiliary(mapOffset)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("transfer: %w", err)
	}

	for section, data := range sectionData {
		section.Data = data
		section.SizeOfRawData = uint32(len(data))
		if section == p.text && section.VirtualSize != 0 {
			section.VirtualSize = uint32(len(data))
		}
	}
	for relocation, value := range relocationValues {
		relocation.VirtualAddress = value
		if relocation.Section == nil {
			relocation.Section = p.text
		}
	}
	keptRelocations := make([]*coff.Relocation, 0, len(p.text.Relocations)-len(p.consumed))
	for _, relocation := range p.text.Relocations {
		if _, remove := p.consumed[relocation]; !remove {
			keptRelocations = append(keptRelocations, relocation)
		}
	}
	p.text.Relocations = keptRelocations
	for symbol, value := range symbolValues {
		symbol.Value = value
	}
	for symbol, records := range auxiliary {
		symbol.AuxiliaryRecords = records
	}
	p.report.BytesAfter = total
	return nil
}

func (p *plan) encodedInstruction(entry *instruction) []byte {
	if entry.removed {
		return nil
	}
	if entry.replacement != nil {
		return entry.replacement
	}
	if !entry.hasFlow || entry.flowReloc || entry.reference.kind == relativeCall || entry.reference.kind == relativeLoop || entry.variant == branchRaw {
		return entry.raw
	}
	if entry.variant == branchShort {
		if entry.reference.kind == relativeJump {
			return []byte{0xeb, 0}
		}
		return []byte{0x70 | entry.reference.cond, 0}
	}
	if entry.variant == branchNear {
		if entry.reference.kind == relativeJump {
			return []byte{0xe9, 0, 0, 0, 0}
		}
		return []byte{0x0f, 0x80 | entry.reference.cond, 0, 0, 0, 0}
	}
	return entry.raw
}

func (p *plan) layout() (map[uint32]uint32, int, error) {
	starts := make(map[uint32]uint32, len(p.instructions)+1)
	var size uint64
	for _, entry := range p.instructions {
		starts[entry.oldStart] = uint32(size)
		size += uint64(len(p.encodedInstruction(entry)))
		if size > math.MaxUint32 || size > uint64(math.MaxInt) {
			return nil, 0, malformed("layout", errors.New("rewritten .text is too large"))
		}
	}
	starts[uint32(len(p.text.Data))] = uint32(size)
	return starts, int(size), nil
}

func (p *plan) relaxBranches(ctx context.Context) error {
	for _, entry := range p.instructions {
		if entry.region != nil && entry.region.isFunction && entry.replacement == nil && !entry.removed && entry.hasFlow && !entry.flowReloc && (entry.reference.kind == relativeJump || entry.reference.kind == relativeConditional) {
			entry.variant = branchShort
		}
	}
	limit := len(p.instructions) + 1
	for iteration := 0; iteration <= limit; iteration++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("transfer: %w", err)
		}
		starts, _, err := p.layout()
		if err != nil {
			return err
		}
		changed := false
		for _, entry := range p.instructions {
			if entry.region == nil || !entry.region.isFunction || entry.removed || entry.replacement != nil || !entry.hasFlow || entry.flowReloc {
				continue
			}
			target64, err := relativeTarget(entry)
			if err != nil || target64 < 0 || target64 >= int64(len(p.text.Data)) {
				return malformed("branch relaxation", fmt.Errorf("branch %#x has invalid target", entry.oldStart))
			}
			target, ok := starts[uint32(target64)]
			if !ok {
				return malformed("branch relaxation", fmt.Errorf("branch %#x target %#x was not laid out", entry.oldStart, target64))
			}
			start := starts[entry.oldStart]
			switch entry.reference.kind {
			case relativeJump, relativeConditional:
				if entry.variant == branchNear {
					continue
				}
				displacement := int64(target) - int64(start+2)
				if displacement < math.MinInt8 || displacement > math.MaxInt8 {
					entry.variant = branchNear
					p.report.RelaxedBranches++
					changed = true
				}
			case relativeLoop:
				displacement := int64(target) - int64(start+uint32(len(entry.raw)))
				if displacement < math.MinInt8 || displacement > math.MaxInt8 {
					return &BranchRangeError{Function: entry.region.name, Offset: entry.oldStart, Target: uint32(target64)}
				}
			}
		}
		if !changed {
			return nil
		}
	}
	return malformed("branch relaxation", errors.New("did not converge"))
}

func (p *plan) patchControlFlow(output []byte, starts map[uint32]uint32, mapOffset func(uint32) (uint32, error)) error {
	for _, entry := range p.instructions {
		if entry.removed {
			continue
		}
		encoded := p.encodedInstruction(entry)
		start := starts[entry.oldStart]
		if entry.replacement == nil && entry.region != nil && entry.region.isFunction && entry.hasFlow && !entry.flowReloc {
			target64, err := relativeTarget(entry)
			if err != nil || target64 < 0 || target64 >= int64(len(p.text.Data)) {
				return malformed("branch repair", fmt.Errorf("branch %#x has invalid target", entry.oldStart))
			}
			target, err := mapOffset(uint32(target64))
			if err != nil {
				return malformed("branch repair", fmt.Errorf("branch %#x: %w", entry.oldStart, err))
			}
			fieldOffset, fieldSize := entry.reference.offset, entry.reference.size
			if entry.variant == branchShort {
				fieldOffset, fieldSize = 1, 1
			} else if entry.variant == branchNear {
				if entry.reference.kind == relativeJump {
					fieldOffset = 1
				} else {
					fieldOffset = 2
				}
				fieldSize = 4
			}
			displacement := int64(target) - int64(start+uint32(len(encoded)))
			if err := writeDisplacement(output, start+uint32(fieldOffset), fieldSize, displacement); err != nil {
				return fmt.Errorf("transfer: branch %#x: %w", entry.oldStart, err)
			}
		}
		if entry.replacement == nil && entry.region != nil && entry.region.isFunction && hasRIPOperand(entry.operands) && !p.hasRelocationCoveringRIP(entry) {
			field, err := ripDisplacementField(entry)
			if err != nil {
				return flowError(entry, err.Error())
			}
			oldDisplacement := int64(int32(binary.LittleEndian.Uint32(entry.raw[field : field+4])))
			oldTarget := int64(entry.oldEnd) + oldDisplacement
			if oldTarget < 0 || oldTarget >= int64(len(p.text.Data)) || p.labels[uint32(oldTarget)] == nil {
				return flowError(entry, fmt.Sprintf("unrelocated RIP-relative target %#x has no local code symbol", oldTarget))
			}
			newTarget, err := mapOffset(uint32(oldTarget))
			if err != nil {
				return flowError(entry, err.Error())
			}
			displacement := int64(newTarget) - int64(start+uint32(len(encoded)))
			if err := writeDisplacement(output, start+uint32(field), 4, displacement); err != nil {
				return flowError(entry, err.Error())
			}
		}
	}
	return nil
}

func writeDisplacement(output []byte, field uint32, size int, value int64) error {
	if uint64(field)+uint64(size) > uint64(len(output)) {
		return errors.New("displacement field is out of bounds")
	}
	if size == 1 {
		if value < math.MinInt8 || value > math.MaxInt8 {
			return ErrBranchRange
		}
		output[field] = byte(int8(value))
		return nil
	}
	if size != 4 {
		return fmt.Errorf("unsupported displacement width %d", size)
	}
	if value < math.MinInt32 || value > math.MaxInt32 {
		return ErrBranchRange
	}
	binary.LittleEndian.PutUint32(output[field:field+4], uint32(int32(value)))
	return nil
}

func hasRIPOperand(operands string) bool { return containsToken(operands, "rip") }

func (p *plan) hasRelocationCoveringRIP(entry *instruction) bool {
	for _, relocation := range entry.relocations {
		if _, consumed := p.consumed[relocation.relocation]; consumed {
			continue
		}
		offset := int(relocation.offset)
		if relocation.width == 4 && offset > 0 && offset+4 == len(entry.raw) && entry.raw[offset-1]&0xc7 == 0x05 {
			return true
		}
	}
	return false
}

func ripDisplacementField(entry *instruction) (int, error) {
	raw := entry.raw
	position := 0
	for position < len(raw) {
		switch raw[position] {
		case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0xf0, 0xf2, 0xf3:
			position++
			continue
		case 0x67:
			return 0, errors.New("address-size override prevents a provable RIP-relative form")
		}
		break
	}
	rex := byte(0)
	if position < len(raw) && raw[position] >= 0x40 && raw[position] <= 0x4f {
		rex = raw[position]
		position++
	}
	if position >= len(raw) {
		return 0, errors.New("truncated RIP-relative instruction")
	}
	opcode := raw[position]
	position++
	if position >= len(raw) {
		return 0, errors.New("RIP-relative instruction lacks ModRM")
	}
	modRM := raw[position]
	position++
	if modRM>>6 != 0 || modRM&7 != 5 {
		return 0, errors.New("operand text mentions RIP but encoding is not ModRM RIP+disp32")
	}
	supported := false
	switch opcode {
	case 0x8d:
		supported = entry.mnemonic == "lea" && rex&8 != 0
	case 0x8b:
		supported = entry.mnemonic == "mov" && rex&8 != 0
	case 0xff:
		supported = entry.mnemonic == "call" && (modRM>>3)&7 == 2
	}
	if !supported {
		return 0, errors.New("RIP-relative form is outside upstream LocalLabels LEA/MOV/CALL support")
	}
	if position+4 != len(raw) {
		return 0, errors.New("RIP-relative disp32 field has an unexpected trailing encoding")
	}
	return position, nil
}

func (p *plan) rebasedSymbols(mapOffset func(uint32) (uint32, error)) (map[*coff.Symbol]uint32, error) {
	textSymbols := make(map[*coff.Symbol]struct{})
	for _, symbol := range p.object.Symbols {
		if symbol.Section == p.text {
			textSymbols[symbol] = struct{}{}
		}
	}
	for _, symbol := range p.resolved {
		if symbol.Section == p.text {
			textSymbols[symbol] = struct{}{}
		}
	}
	values := make(map[*coff.Symbol]uint32, len(textSymbols))
	for symbol := range textSymbols {
		value, err := mapOffset(symbol.Value)
		if err != nil {
			return nil, malformed("symbol rebasing", fmt.Errorf("symbol %q: %w", symbol.Name, err))
		}
		values[symbol] = value
	}
	return values, nil
}

func (p *plan) rebasedRelocationAddresses(starts map[uint32]uint32) (map[*coff.Relocation]uint32, error) {
	values := make(map[*coff.Relocation]uint32, len(p.text.Relocations)-len(p.consumed))
	for _, entry := range p.instructions {
		start := starts[entry.oldStart]
		encoded := p.encodedInstruction(entry)
		for _, relative := range entry.relocations {
			if _, consumed := p.consumed[relative.relocation]; consumed {
				continue
			}
			if entry.removed || entry.replacement != nil || uint64(relative.offset)+uint64(relative.width) > uint64(len(encoded)) {
				return nil, malformed("relocation rebasing", fmt.Errorf("relocation offset escaped rewritten instruction %#x", entry.oldStart))
			}
			values[relative.relocation] = start + relative.offset
		}
	}
	return values, nil
}

func (p *plan) rebasedRelocationAddends(textOutput []byte, relocationValues map[*coff.Relocation]uint32, symbolValues map[*coff.Symbol]uint32, mapOffset func(uint32) (uint32, error)) (map[*coff.Section][]byte, error) {
	sectionData := map[*coff.Section][]byte{p.text: textOutput}
	for _, section := range p.object.Sections {
		for _, relocation := range section.Relocations {
			if _, consumed := p.consumed[relocation]; consumed {
				continue
			}
			symbol := p.resolved[relocation]
			if symbol == nil || symbol.Section != p.text {
				continue
			}
			width, err := relocationWidth(relocation.Type)
			if err != nil {
				return nil, malformed("relocation addend rebasing", err)
			}
			oldAddress := relocation.VirtualAddress
			newAddress := oldAddress
			if value, ok := relocationValues[relocation]; ok {
				newAddress = value
			}
			oldAddend, err := readSignedAddend(section.Data, oldAddress, width)
			if err != nil {
				return nil, malformed("relocation addend rebasing", fmt.Errorf("relocation %#x: %w", oldAddress, err))
			}
			oldTarget := int64(symbol.Value) + oldAddend
			if oldTarget < 0 || oldTarget > int64(len(p.text.Data)) {
				continue
			}
			mappedTarget, err := mapOffset(uint32(oldTarget))
			if err != nil {
				return nil, malformed("relocation addend rebasing", fmt.Errorf("relocation %#x target: %w", oldAddress, err))
			}
			newSymbol, ok := symbolValues[symbol]
			if !ok {
				return nil, malformed("relocation addend rebasing", fmt.Errorf("target symbol %q was not rebased", symbol.Name))
			}
			data := sectionData[section]
			if data == nil {
				data = append([]byte(nil), section.Data...)
				sectionData[section] = data
			}
			if err := writeSignedAddend(data, newAddress, width, int64(mappedTarget)-int64(newSymbol)); err != nil {
				return nil, malformed("relocation addend rebasing", fmt.Errorf("relocation %#x: %w", oldAddress, err))
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

func (p *plan) codeLayoutChanged(starts map[uint32]uint32, total int) bool {
	if total != len(p.text.Data) {
		return true
	}
	for _, entry := range p.instructions {
		if starts[entry.oldStart] != entry.oldStart || entry.replacement != nil || entry.removed || len(p.encodedInstruction(entry)) != len(entry.raw) {
			return true
		}
	}
	return false
}

func (p *plan) validateExistingUnwind(layoutChanged bool) error {
	if !layoutChanged {
		return nil
	}
	for _, section := range p.object.Sections {
		if !strings.HasPrefix(section.Name, ".pdata") {
			continue
		}
		if len(section.Data)%12 != 0 {
			return &UnwindError{Section: section.Name, Reason: "data is not a sequence of 12-byte RUNTIME_FUNCTION records"}
		}
		for record := 0; record < len(section.Data); record += 12 {
			for _, field := range []uint32{uint32(record), uint32(record + 4)} {
				covered := false
				for _, relocation := range section.Relocations {
					if relocation.VirtualAddress == field {
						symbol := p.resolved[relocation]
						if symbol != nil && symbol.Section == p.text {
							covered = true
							break
						}
					}
				}
				if !covered {
					return &UnwindError{Section: section.Name, Offset: field, Reason: "runtime-function boundary lacks a .text relocation"}
				}
			}
		}
	}
	return nil
}

func (p *plan) rebasedFunctionAuxiliary(mapOffset func(uint32) (uint32, error)) (map[*coff.Symbol][][]byte, error) {
	result := make(map[*coff.Symbol][][]byte)
	for _, symbol := range p.object.Symbols {
		if symbol.Section != p.text || !symbol.IsFunction() || len(symbol.AuxiliaryRecords) == 0 {
			continue
		}
		if len(symbol.AuxiliaryRecords[0]) != 18 {
			return nil, malformed("auxiliary rebasing", fmt.Errorf("function %q has malformed auxiliary record", symbol.Name))
		}
		var region *codeRegion
		for _, candidate := range p.regions {
			if candidate.isFunction && candidate.name == symbol.Name && candidate.start == symbol.Value {
				region = candidate
				break
			}
		}
		if region == nil {
			continue
		}
		start, err := mapOffset(region.start)
		if err != nil {
			return nil, malformed("auxiliary rebasing", err)
		}
		end, err := mapOffset(region.end)
		if err != nil {
			return nil, malformed("auxiliary rebasing", err)
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
