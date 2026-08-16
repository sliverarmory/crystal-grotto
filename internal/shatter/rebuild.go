// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package shatter

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

type layoutResult struct {
	fragmentStarts map[*fragment]uint32
	oldStarts      map[uint32]uint32
	regionStarts   map[*region]uint32
	regionEnds     map[*region]uint32
	size           int
}

func (p *plan) finish(ctx context.Context) error {
	if err := p.relaxBranches(ctx); err != nil {
		return err
	}
	layout, err := p.layout()
	if err != nil {
		return err
	}
	mapOffset := func(old uint32) (uint32, error) {
		if value, ok := layout.oldStarts[old]; ok {
			return value, nil
		}
		entry := instructionAt(p.instructions, old)
		if entry == nil {
			return 0, fmt.Errorf("offset %#x is outside .text", old)
		}
		fragment := p.byEntry[entry]
		if fragment == nil {
			return 0, fmt.Errorf("instruction %#x has no output fragment", entry.oldStart)
		}
		if len(fragment.output) != len(entry.raw) || fragment.removed || fragment.expanded {
			return 0, fmt.Errorf("offset %#x points inside resized instruction %#x", old, entry.oldStart)
		}
		return layout.fragmentStarts[fragment] + old - entry.oldStart, nil
	}

	output := make([]byte, layout.size)
	for _, fragment := range p.fragments {
		copy(output[layout.fragmentStarts[fragment]:], fragment.output)
	}
	if err := p.patchReferences(output, layout, mapOffset); err != nil {
		return err
	}
	symbolValues, err := p.rebasedSymbols(mapOffset)
	if err != nil {
		return err
	}
	relocationValues, err := p.rebasedRelocationAddresses(layout)
	if err != nil {
		return err
	}
	sectionData, err := p.rebasedRelocationAddends(output, relocationValues, symbolValues, mapOffset)
	if err != nil {
		return err
	}
	auxiliary, err := p.rebasedFunctionAuxiliary(layout)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("shatter: %w", err)
	}

	// Commit every planned mutation together, preserving graph pointer identity.
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
	for symbol, value := range symbolValues {
		symbol.Value = value
	}
	for symbol, records := range auxiliary {
		symbol.AuxiliaryRecords = records
	}
	return nil
}

func (p *plan) layout() (*layoutResult, error) {
	result := &layoutResult{
		fragmentStarts: make(map[*fragment]uint32, len(p.fragments)),
		oldStarts:      make(map[uint32]uint32, len(p.instructions)+1),
		regionStarts:   make(map[*region]uint32, len(p.regions)),
		regionEnds:     make(map[*region]uint32, len(p.regions)),
	}
	var size uint64
	var active *region
	for _, fragment := range p.fragments {
		if fragment.region != active {
			if active != nil {
				result.regionEnds[active] = uint32(size)
			}
			active = fragment.region
			result.regionStarts[active] = uint32(size)
		}
		result.fragmentStarts[fragment] = uint32(size)
		if fragment.entry != nil {
			result.oldStarts[fragment.entry.oldStart] = uint32(size)
		}
		size += uint64(len(fragment.output))
		if size > math.MaxUint32 || size > uint64(math.MaxInt) {
			return nil, errors.New("shatter: rewritten .text is too large")
		}
	}
	if active != nil {
		result.regionEnds[active] = uint32(size)
	}
	result.oldStarts[uint32(len(p.text.Data))] = uint32(size)
	result.size = int(size)
	return result, nil
}

func (p *plan) relaxBranches(ctx context.Context) error {
	for iteration := 0; iteration <= len(p.fragments); iteration++ {
		layout, err := p.layout()
		if err != nil {
			return err
		}
		changed := false
		for _, fragment := range p.fragments {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("shatter: %w", err)
			}
			kind, oldTarget, patch, short := branchDescription(fragment)
			if !patch || !short || fragment.expanded {
				continue
			}
			newTarget, ok := layout.oldStarts[oldTarget]
			if !ok {
				return fmt.Errorf("shatter: branch target %#x has no output label", oldTarget)
			}
			start := layout.fragmentStarts[fragment]
			displacement := int64(newTarget) - int64(start+uint32(len(fragment.output)))
			if displacement >= math.MinInt8 && displacement <= math.MaxInt8 {
				continue
			}
			switch kind {
			case relativeJump:
				fragment.output = []byte{0xe9, 0, 0, 0, 0}
			case relativeConditional:
				if fragment.entry == nil || len(fragment.output) == 0 {
					return errors.New("shatter: conditional connector has no source opcode")
				}
				condition := fragment.output[0] & 0x0f
				fragment.output = []byte{0x0f, 0x80 | condition, 0, 0, 0, 0}
			case relativeLoop:
				if fragment.entry == nil {
					return errors.New("shatter: LOOP connector has no source instruction")
				}
				return p.unsupported(fragment.entry, "LOOP/JCXZ short target overflows after block shattering and has no Iced-equivalent near form")
			default:
				return errors.New("shatter: unsupported short branch during relaxation")
			}
			fragment.expanded = true
			p.report.ExpandedBranches++
			changed = true
		}
		if !changed {
			return nil
		}
	}
	return errors.New("shatter: branch relaxation did not converge")
}

func branchDescription(fragment *fragment) (kind relativeKind, oldTarget uint32, patch, short bool) {
	if fragment == nil || fragment.removed {
		return relativeNone, 0, false, false
	}
	if fragment.connector {
		return relativeJump, fragment.target, true, len(fragment.output) == 2
	}
	entry := fragment.entry
	if entry == nil || !entry.hasRelative || len(entry.relocations) != 0 {
		return relativeNone, 0, false, false
	}
	if entry.target < 0 || entry.target > math.MaxUint32 {
		return entry.relative.kind, 0, false, false
	}
	return entry.relative.kind, uint32(entry.target), true, len(fragment.output) == 2
}

func (p *plan) patchReferences(output []byte, layout *layoutResult, mapOffset func(uint32) (uint32, error)) error {
	for _, fragment := range p.fragments {
		kind, oldTarget, patch, _ := branchDescription(fragment)
		if patch {
			newTarget, err := mapOffset(oldTarget)
			if err != nil {
				return fmt.Errorf("shatter: branch to %#x: %w", oldTarget, err)
			}
			if err := patchBranch(output, layout.fragmentStarts[fragment], fragment.output, kind, newTarget); err != nil {
				if fragment.entry != nil {
					return fmt.Errorf("shatter: branch at %#x: %w", fragment.entry.oldStart, err)
				}
				return fmt.Errorf("shatter: connector to %#x: %w", oldTarget, err)
			}
		}
		entry := fragment.entry
		if entry == nil || !entry.ripRelative || len(entry.relocations) != 0 {
			continue
		}
		newTarget, err := mapOffset(entry.ripTarget)
		if err != nil {
			return fmt.Errorf("shatter: RIP-relative instruction %#x: %w", entry.oldStart, err)
		}
		start := layout.fragmentStarts[fragment]
		displacement := int64(newTarget) - int64(start+uint32(len(fragment.output)))
		if displacement < math.MinInt32 || displacement > math.MaxInt32 {
			return p.unsupported(entry, "RIP-relative displacement overflows rel32 after block shattering")
		}
		field := uint64(start) + uint64(entry.ripDisp)
		if field+4 > uint64(len(output)) {
			return fmt.Errorf("shatter: RIP-relative field at %#x is out of bounds", entry.oldStart)
		}
		binary.LittleEndian.PutUint32(output[field:field+4], uint32(int32(displacement)))
	}
	return nil
}

func patchBranch(output []byte, start uint32, encoded []byte, kind relativeKind, target uint32) error {
	if len(encoded) == 0 {
		return nil
	}
	fieldOffset, fieldSize := 0, 0
	switch {
	case len(encoded) == 2 && (encoded[0] == 0xeb || encoded[0] >= 0x70 && encoded[0] <= 0x7f || encoded[0] >= 0xe0 && encoded[0] <= 0xe3):
		fieldOffset, fieldSize = 1, 1
	case len(encoded) == 5 && (encoded[0] == 0xe8 || encoded[0] == 0xe9):
		fieldOffset, fieldSize = 1, 4
	case len(encoded) == 6 && encoded[0] == 0x0f && encoded[1] >= 0x80 && encoded[1] <= 0x8f:
		fieldOffset, fieldSize = 2, 4
	default:
		return fmt.Errorf("unsupported %v encoding %x", kind, encoded)
	}
	displacement := int64(target) - int64(start) - int64(len(encoded))
	field := uint64(start) + uint64(fieldOffset)
	if field+uint64(fieldSize) > uint64(len(output)) {
		return errors.New("relative field is out of bounds")
	}
	if fieldSize == 1 {
		if displacement < math.MinInt8 || displacement > math.MaxInt8 {
			return errors.New("short branch still overflows after relaxation")
		}
		output[field] = byte(int8(displacement))
		return nil
	}
	if displacement < math.MinInt32 || displacement > math.MaxInt32 {
		return errors.New("rel32 overflows after block shattering")
	}
	binary.LittleEndian.PutUint32(output[field:field+4], uint32(int32(displacement)))
	return nil
}

func (p *plan) rebasedSymbols(mapOffset func(uint32) (uint32, error)) (map[*coff.Symbol]uint32, error) {
	values := make(map[*coff.Symbol]uint32)
	for _, symbol := range p.object.Symbols {
		if symbol.Section != p.text {
			continue
		}
		if isTextSectionSymbol(symbol, p.text) {
			values[symbol] = 0
			continue
		}
		value, err := mapOffset(symbol.Value)
		if err != nil {
			return nil, fmt.Errorf("shatter: symbol %q: %w", symbol.Name, err)
		}
		values[symbol] = value
	}
	return values, nil
}

func (p *plan) rebasedRelocationAddresses(layout *layoutResult) (map[*coff.Relocation]uint32, error) {
	values := make(map[*coff.Relocation]uint32, len(p.text.Relocations))
	for _, entry := range p.instructions {
		fragment := p.byEntry[entry]
		if fragment == nil {
			return nil, fmt.Errorf("shatter: relocated instruction %#x has no fragment", entry.oldStart)
		}
		start := layout.fragmentStarts[fragment]
		for _, relative := range entry.relocations {
			if uint64(relative.offset)+uint64(relative.width) > uint64(len(fragment.output)) {
				return nil, fmt.Errorf("shatter: relocation offset escaped instruction %#x", entry.oldStart)
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
				return nil, fmt.Errorf("shatter: relocation %#x addend: %w", oldAddress, err)
			}
			oldSymbolValue := relocation.Symbol.Value
			if isTextSectionSymbol(relocation.Symbol, p.text) {
				oldSymbolValue = 0
			}
			oldTarget := int64(oldSymbolValue) + oldAddend
			if oldTarget < 0 || oldTarget > int64(len(p.text.Data)) {
				continue
			}
			mappedTarget, err := mapOffset(uint32(oldTarget))
			if err != nil {
				return nil, fmt.Errorf("shatter: relocation %#x target: %w", oldAddress, err)
			}
			newSymbol, ok := symbolValues[relocation.Symbol]
			if !ok {
				return nil, fmt.Errorf("shatter: relocation %#x target symbol %q was not rebased", oldAddress, relocation.Symbol.Name)
			}
			newAddend := int64(mappedTarget) - int64(newSymbol)
			data := sectionData[section]
			if data == nil {
				data = append([]byte(nil), section.Data...)
				sectionData[section] = data
			}
			if err := writeSignedAddend(data, newAddress, width, newAddend); err != nil {
				return nil, fmt.Errorf("shatter: relocation %#x rebased addend: %w", oldAddress, err)
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

func (p *plan) rebasedFunctionAuxiliary(layout *layoutResult) (map[*coff.Symbol][][]byte, error) {
	result := make(map[*coff.Symbol][][]byte)
	byName := make(map[string]*region, len(p.functions))
	for _, function := range p.functions {
		byName[function.name] = function
	}
	for _, symbol := range p.object.Symbols {
		if symbol.Section != p.text || !symbol.IsFunction() || len(symbol.AuxiliaryRecords) == 0 {
			continue
		}
		if len(symbol.AuxiliaryRecords[0]) != 18 {
			return nil, fmt.Errorf("shatter: function %q has malformed auxiliary record", symbol.Name)
		}
		function := byName[symbol.Name]
		if function == nil {
			continue
		}
		start, startOK := layout.regionStarts[function]
		end, endOK := layout.regionEnds[function]
		if !startOK || !endOK || end < start {
			return nil, fmt.Errorf("shatter: function %q has no physical output region", symbol.Name)
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
