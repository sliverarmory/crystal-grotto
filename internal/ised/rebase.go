// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package ised

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

var (
	// ErrBranchOutOfRange identifies a preserved short/near branch whose
	// original encoding cannot reach after an ised edit. The built-in backend
	// does not silently relax instruction forms without Iced parity evidence.
	ErrBranchOutOfRange = errors.New("ised: branch displacement is out of range")

	// ErrUnsupportedUnwind identifies existing x64 unwind metadata whose
	// boundaries cannot be proven safe for a length-changing rewrite.
	ErrUnsupportedUnwind = errors.New("ised: existing unwind metadata cannot be safely rebased")
)

// BranchRangeError identifies the exact original branch that cannot retain
// its encoding after layout changes.
type BranchRangeError struct {
	Function string
	Section  string
	Offset   uint32
	Target   uint32
	Width    uint8
}

func (e *BranchRangeError) Error() string {
	if e == nil {
		return ErrBranchOutOfRange.Error()
	}
	return fmt.Sprintf("ised: %s:%s branch %#x to %#x no longer fits rel%d", e.Section, e.Function, e.Offset, e.Target, e.Width*8)
}

func (e *BranchRangeError) Unwrap() error { return ErrBranchOutOfRange }

// UnwindError identifies the pdata field that prevents a proven rewrite.
type UnwindError struct {
	Section string
	Offset  uint32
	Reason  string
}

func (e *UnwindError) Error() string {
	if e == nil {
		return ErrUnsupportedUnwind.Error()
	}
	return fmt.Sprintf("ised: unwind section %s at %#x: %s", e.Section, e.Offset, e.Reason)
}

func (e *UnwindError) Unwrap() error { return ErrUnsupportedUnwind }

// RebaseBackend applies arbitrary-length raw ised insertions/replacements while
// preserving every proven original instruction encoding. It repairs local
// relative fields, symbols, relocations, section-symbol addends, function
// auxiliary sizes, and relocation-backed pdata ranges. It deliberately does
// not relax branch forms or synthesize unwind opcodes.
type RebaseBackend struct {
	Context context.Context
}

var _ RewriteBackend = RebaseBackend{}

func (backend RebaseBackend) RewriteISED(object *coff.Object, program Program, plan Plan) error {
	ctx := backend.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if object == nil {
		return fmt.Errorf("%w: nil COFF object", ErrInvalidObject)
	}
	if object.Machine != plan.Machine || object.Machine != program.Machine {
		return fmt.Errorf("%w: object/program/plan machines differ", ErrInvalidObject)
	}

	editsBySection := make(map[string][]Edit)
	for _, edit := range plan.Edits {
		editsBySection[edit.Section] = append(editsBySection[edit.Section], edit)
	}
	layouts := make(map[*coff.Section]*sectionLayout, len(editsBySection))
	layoutByName := make(map[string]*sectionLayout, len(editsBySection))
	sectionNames := make([]string, 0, len(editsBySection))
	for name := range editsBySection {
		sectionNames = append(sectionNames, name)
	}
	sort.Strings(sectionNames)
	for _, name := range sectionNames {
		edits := editsBySection[name]
		section := object.GetSection(name)
		if section == nil {
			return fmt.Errorf("%w: missing edited section %q", ErrInvalidObject, name)
		}
		layout, err := buildSectionLayout(section, edits)
		if err != nil {
			return err
		}
		layouts[section], layoutByName[name] = layout, layout
	}

	for _, function := range program.Functions {
		layout := layoutByName[function.Section]
		if layout == nil || !layout.structural {
			continue
		}
		section := object.GetSection(function.Section)
		for _, instruction := range function.Instructions {
			if err := ctx.Err(); err != nil {
				return err
			}
			edit := layout.byStart[instruction.Offset]
			if edit != nil && edit.edit.Replace != nil {
				continue
			}
			if instruction.PCRelativeUnknown {
				field := instruction.Offset + uint32(instruction.RelativeOffset)
				if instruction.PCRelative && relocationCovers(section, field, uint32(instruction.RelativeWidth), object.Machine) {
					continue
				}
				return &BoundaryError{
					Function: function.Name, Section: function.Section, Offset: instruction.Offset,
					Feature: "unclassified PC-relative encoding during layout change", Err: ErrSemanticDetailUnavailable,
				}
			}
		}
	}

	symbolValues, auxiliary, err := prepareSymbolRebase(object, layouts)
	if err != nil {
		return err
	}
	relocations, resolved, err := prepareRelocationRebase(object, layouts)
	if err != nil {
		return err
	}
	data := make(map[*coff.Section][]byte, len(layouts))
	for section, layout := range layouts {
		data[section] = append([]byte(nil), layout.output...)
	}
	if err := repairRelativeInstructions(program, layouts, data, object); err != nil {
		return err
	}
	if err := validateUnwind(plan, object, layouts, resolved); err != nil {
		return err
	}
	if err := prepareRebasedAddends(object, layouts, symbolValues, relocations, resolved, data); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Commit only after every byte, range, and object relationship validates.
	for section, replacement := range data {
		section.Data = replacement
		section.SizeOfRawData = uint32(len(replacement))
		if layout := layouts[section]; layout != nil && section.VirtualSize != 0 {
			section.VirtualSize = uint32(len(replacement))
		}
	}
	for symbol, value := range symbolValues {
		symbol.Value = value
	}
	for relocation, value := range relocations {
		relocation.VirtualAddress = value
		if relocation.Section == nil {
			relocation.Section = parentSection(object, relocation)
		}
	}
	for symbol, records := range auxiliary {
		symbol.AuxiliaryRecords = records
	}
	return nil
}

type laidOutEdit struct {
	edit             Edit
	oldStart         uint32
	oldEnd           uint32
	newStart         uint32
	newOriginalStart uint32
	newEnd           uint32
	emitted          []byte
}

type sectionLayout struct {
	section    *coff.Section
	oldData    []byte
	output     []byte
	edits      []*laidOutEdit
	byStart    map[uint32]*laidOutEdit
	modified   bool
	structural bool
}

func buildSectionLayout(section *coff.Section, edits []Edit) (*sectionLayout, error) {
	if uint64(len(section.Data)) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: section %s exceeds the COFF address space", ErrInvalidObject, section.Name)
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].Original.Offset < edits[j].Original.Offset })
	layout := &sectionLayout{
		section: section, oldData: append([]byte(nil), section.Data...),
		byStart: make(map[uint32]*laidOutEdit, len(edits)),
	}
	var oldCursor uint32
	var newSize uint64
	for _, edit := range edits {
		layout.modified = true
		start := edit.Original.Offset
		end64 := uint64(start) + uint64(len(edit.Original.Bytes))
		if start < oldCursor || end64 > uint64(len(section.Data)) {
			return nil, fmt.Errorf("%w: overlapping or out-of-bounds edit in %s at %#x", ErrInvalidProgram, section.Name, start)
		}
		end := uint32(end64)
		if !bytes.Equal(section.Data[start:end], edit.Original.Bytes) {
			return nil, fmt.Errorf("%w: source bytes changed in %s at %#x", ErrInvalidProgram, section.Name, start)
		}
		if _, duplicate := layout.byStart[start]; duplicate {
			return nil, fmt.Errorf("%w: duplicate edit in %s at %#x", ErrInvalidProgram, section.Name, start)
		}
		newSize += uint64(start - oldCursor)
		if newSize > math.MaxUint32 || newSize > math.MaxInt {
			return nil, fmt.Errorf("%w: rewritten section %s is too large", ErrInvalidObject, section.Name)
		}
		emitted := renderEdit(edit)
		if uint64(len(emitted)) > math.MaxUint32 {
			return nil, fmt.Errorf("%w: emitted edit in %s at %#x exceeds the COFF address space", ErrInvalidObject, section.Name, start)
		}
		entry := &laidOutEdit{
			edit: edit, oldStart: start, oldEnd: end, newStart: uint32(newSize),
			emitted: append([]byte(nil), emitted...),
		}
		prepend := 0
		if edit.Prepend != nil {
			prepend = len(edit.Prepend.Content)
		}
		if uint64(prepend) > math.MaxUint32 || newSize+uint64(prepend) > math.MaxUint32 {
			return nil, fmt.Errorf("%w: prepend in %s at %#x exceeds the COFF address space", ErrInvalidObject, section.Name, start)
		}
		entry.newOriginalStart = entry.newStart + uint32(prepend)
		newSize += uint64(len(emitted))
		if newSize > math.MaxUint32 || newSize > math.MaxInt {
			return nil, fmt.Errorf("%w: rewritten section %s is too large", ErrInvalidObject, section.Name)
		}
		entry.newEnd = uint32(newSize)
		layout.edits = append(layout.edits, entry)
		layout.byStart[start] = entry
		prependLength, appendLength := 0, 0
		if edit.Prepend != nil {
			prependLength = len(edit.Prepend.Content)
		}
		if edit.Append != nil {
			appendLength = len(edit.Append.Content)
		}
		if len(emitted) != len(edit.Original.Bytes) || prependLength != 0 || appendLength != 0 {
			layout.structural = true
		}
		oldCursor = end
	}
	newSize += uint64(len(section.Data)) - uint64(oldCursor)
	if newSize > math.MaxUint32 || newSize > math.MaxInt {
		return nil, fmt.Errorf("%w: rewritten section %s is too large", ErrInvalidObject, section.Name)
	}
	layout.output = make([]byte, int(newSize))
	oldCursor, newCursor := uint32(0), uint32(0)
	for _, edit := range layout.edits {
		copied := edit.oldStart - oldCursor
		copy(layout.output[newCursor:newCursor+copied], section.Data[oldCursor:edit.oldStart])
		newCursor += copied
		copy(layout.output[newCursor:newCursor+uint32(len(edit.emitted))], edit.emitted)
		newCursor += uint32(len(edit.emitted))
		oldCursor = edit.oldEnd
	}
	copy(layout.output[newCursor:], section.Data[oldCursor:])
	return layout, nil
}

func (layout *sectionLayout) mapOffset(old uint32) (uint32, error) {
	if uint64(old) > uint64(len(layout.oldData)) {
		return 0, fmt.Errorf("offset %#x is outside section %s", old, layout.section.Name)
	}
	var delta int64
	for _, edit := range layout.edits {
		if old < edit.oldStart {
			return addDelta(old, delta)
		}
		if old == edit.oldStart {
			return edit.newStart, nil
		}
		if old < edit.oldEnd {
			if edit.edit.Replace != nil {
				return 0, fmt.Errorf("offset %#x points inside replaced instruction %#x", old, edit.oldStart)
			}
			return edit.newOriginalStart + old - edit.oldStart, nil
		}
		delta += int64(len(edit.emitted)) - int64(edit.oldEnd-edit.oldStart)
		if old == edit.oldEnd {
			return edit.newEnd, nil
		}
	}
	return addDelta(old, delta)
}

func (layout *sectionLayout) mapOriginalOffset(old uint32) (uint32, error) {
	for _, edit := range layout.edits {
		if old >= edit.oldStart && old < edit.oldEnd {
			if edit.edit.Replace != nil {
				return 0, fmt.Errorf("offset %#x points inside replaced instruction %#x", old, edit.oldStart)
			}
			return edit.newOriginalStart + old - edit.oldStart, nil
		}
	}
	return layout.mapOffset(old)
}

func (layout *sectionLayout) mapBranchTarget(old uint32, before bool) (uint32, error) {
	if !before {
		if edit := layout.byStart[old]; edit != nil {
			return edit.newOriginalStart, nil
		}
	}
	return layout.mapOffset(old)
}

func addDelta(value uint32, delta int64) (uint32, error) {
	result := int64(value) + delta
	if result < 0 || result > math.MaxUint32 {
		return 0, errors.New("rebased offset exceeds the COFF address space")
	}
	return uint32(result), nil
}

func prepareSymbolRebase(object *coff.Object, layouts map[*coff.Section]*sectionLayout) (map[*coff.Symbol]uint32, map[*coff.Symbol][][]byte, error) {
	values := make(map[*coff.Symbol]uint32)
	auxiliary := make(map[*coff.Symbol][][]byte)
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return nil, nil, fmt.Errorf("%w: symbol %d is nil", ErrInvalidObject, index)
		}
		layout := layouts[symbol.Section]
		if layout == nil {
			continue
		}
		value, err := layout.mapOffset(symbol.Value)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: rebase symbol %q: %v", ErrInvalidObject, symbol.Name, err)
		}
		values[symbol] = value
	}

	for _, section := range object.Sections {
		layout := layouts[section]
		if layout == nil {
			continue
		}
		if !layout.structural {
			continue
		}
		var codeSymbols []*coff.Symbol
		for _, symbol := range object.Symbols {
			if symbol.Section == section && (symbol.IsFunction() || symbol.IsGlobalVariable()) {
				codeSymbols = append(codeSymbols, symbol)
			}
		}
		sort.SliceStable(codeSymbols, func(i, j int) bool { return codeSymbols[i].Value < codeSymbols[j].Value })
		for index, symbol := range codeSymbols {
			if !symbol.IsFunction() || len(symbol.AuxiliaryRecords) == 0 {
				continue
			}
			if len(symbol.AuxiliaryRecords[0]) != 18 {
				return nil, nil, fmt.Errorf("%w: function %q has malformed auxiliary record", ErrInvalidObject, symbol.Name)
			}
			end := uint32(len(layout.oldData))
			if index+1 < len(codeSymbols) {
				end = codeSymbols[index+1].Value
			}
			newStart := values[symbol]
			newEnd, err := layout.mapOffset(end)
			if err != nil || newEnd < newStart {
				return nil, nil, fmt.Errorf("%w: rebase auxiliary size for %q", ErrInvalidObject, symbol.Name)
			}
			records := cloneAuxiliary(symbol.AuxiliaryRecords)
			binary.LittleEndian.PutUint32(records[0][4:8], newEnd-newStart)
			auxiliary[symbol] = records
		}
	}
	return values, auxiliary, nil
}

func cloneAuxiliary(records [][]byte) [][]byte {
	result := make([][]byte, len(records))
	for index, record := range records {
		result[index] = append([]byte(nil), record...)
	}
	return result
}

func prepareRelocationRebase(object *coff.Object, layouts map[*coff.Section]*sectionLayout) (map[*coff.Relocation]uint32, map[*coff.Relocation]*coff.Symbol, error) {
	values := make(map[*coff.Relocation]uint32)
	resolved := make(map[*coff.Relocation]*coff.Symbol)
	knownSections := make(map[*coff.Section]struct{}, len(object.Sections))
	knownSymbols := make(map[*coff.Symbol]struct{}, len(object.Symbols))
	for _, section := range object.Sections {
		if section != nil {
			knownSections[section] = struct{}{}
		}
	}
	for _, symbol := range object.Symbols {
		if symbol != nil {
			knownSymbols[symbol] = struct{}{}
		}
	}
	for sectionIndex, section := range object.Sections {
		if section == nil {
			return nil, nil, fmt.Errorf("%w: section %d is nil", ErrInvalidObject, sectionIndex)
		}
		if section.Object != nil && section.Object != object {
			return nil, nil, fmt.Errorf("%w: section %q belongs to another object", ErrInvalidObject, section.Name)
		}
		for relocationIndex, relocation := range section.Relocations {
			if relocation == nil {
				return nil, nil, fmt.Errorf("%w: section %s relocation %d is nil", ErrInvalidObject, section.Name, relocationIndex)
			}
			if relocation.Section != nil && relocation.Section != section {
				return nil, nil, fmt.Errorf("%w: section %s relocation %d has a foreign parent", ErrInvalidObject, section.Name, relocationIndex)
			}
			symbol := relocation.Symbol
			if symbol == nil && relocation.SymbolName != "" {
				symbol = object.GetSymbol(relocation.SymbolName)
			}
			if symbol == nil {
				return nil, nil, fmt.Errorf("%w: section %s relocation %d references missing symbol %q", ErrInvalidObject, section.Name, relocationIndex, relocation.SymbolName)
			}
			if _, ok := knownSymbols[symbol]; !ok {
				return nil, nil, fmt.Errorf("%w: section %s relocation %d references a foreign symbol", ErrInvalidObject, section.Name, relocationIndex)
			}
			if symbol.Section != nil {
				if _, ok := knownSections[symbol.Section]; !ok {
					return nil, nil, fmt.Errorf("%w: relocation target %q has a foreign section", ErrInvalidObject, symbol.Name)
				}
			}
			resolved[relocation] = symbol
			value := relocation.VirtualAddress
			if layout := layouts[section]; layout != nil {
				width, widthErr := coffRelocationWidth(object.Machine, relocation.Type)
				if widthErr != nil {
					return nil, nil, &BoundaryError{Section: section.Name, Offset: relocation.VirtualAddress, Feature: "relocation field during layout change", Err: errors.Join(ErrSemanticDetailUnavailable, widthErr)}
				}
				if uint64(relocation.VirtualAddress)+uint64(width) > uint64(len(layout.oldData)) {
					return nil, nil, fmt.Errorf("%w: section %s relocation %d field is out of bounds", ErrInvalidObject, section.Name, relocationIndex)
				}
				var err error
				value, err = layout.mapOriginalOffset(relocation.VirtualAddress)
				if err != nil {
					return nil, nil, fmt.Errorf("%w: rebase %s relocation %d: %v", ErrInvalidObject, section.Name, relocationIndex, err)
				}
				if uint64(value)+uint64(width) > uint64(len(layout.output)) {
					return nil, nil, fmt.Errorf("%w: rebased section %s relocation %d field is out of bounds", ErrInvalidObject, section.Name, relocationIndex)
				}
			}
			values[relocation] = value
		}
	}
	return values, resolved, nil
}

func repairRelativeInstructions(program Program, layouts map[*coff.Section]*sectionLayout, data map[*coff.Section][]byte, object *coff.Object) error {
	for _, function := range program.Functions {
		section := object.GetSection(function.Section)
		layout := layouts[section]
		if layout == nil || !layout.structural {
			continue
		}
		for _, instruction := range function.Instructions {
			if !instruction.PCRelative || instruction.PCRelativeUnknown {
				continue
			}
			if edit := layout.byStart[instruction.Offset]; edit != nil && edit.edit.Replace != nil {
				continue
			}
			fieldOld := instruction.Offset + uint32(instruction.RelativeOffset)
			if relocationCovers(section, fieldOld, uint32(instruction.RelativeWidth), object.Machine) {
				continue
			}
			if uint64(instruction.RelativeTarget) > uint64(len(layout.oldData)) {
				return &BoundaryError{Function: function.Name, Section: function.Section, Offset: instruction.Offset, Feature: "PC-relative target outside .text", Err: ErrSemanticDetailUnavailable}
			}
			target, err := layout.mapBranchTarget(instruction.RelativeTarget, instruction.RelativeTargetBefore)
			if err != nil {
				return &BoundaryError{Function: function.Name, Section: function.Section, Offset: instruction.Offset, Feature: "PC-relative target mapping", Err: errors.Join(ErrSemanticDetailUnavailable, err)}
			}
			start, err := layout.mapOriginalOffset(instruction.Offset)
			if err != nil {
				return fmt.Errorf("%w: rebase instruction %s+%#x: %v", ErrInvalidObject, function.Section, instruction.Offset, err)
			}
			end := uint64(start) + uint64(len(instruction.Bytes))
			if end > uint64(len(data[section])) {
				return fmt.Errorf("%w: rebased instruction exceeds %s", ErrInvalidObject, function.Section)
			}
			displacement := int64(target) - int64(end)
			field := start + uint32(instruction.RelativeOffset)
			if err := writeRelative(data[section], field, instruction.RelativeWidth, displacement); err != nil {
				if errors.Is(err, ErrBranchOutOfRange) {
					return &BranchRangeError{Function: function.Name, Section: function.Section, Offset: instruction.Offset, Target: instruction.RelativeTarget, Width: instruction.RelativeWidth}
				}
				return fmt.Errorf("%w: patch relative instruction: %v", ErrInvalidObject, err)
			}
		}
	}
	return nil
}

func relocationCovers(section *coff.Section, field, width uint32, machine coff.Machine) bool {
	for _, relocation := range section.Relocations {
		if relocation == nil {
			continue
		}
		relocationWidth, err := coffRelocationWidth(machine, relocation.Type)
		if err != nil {
			continue
		}
		if relocation.VirtualAddress <= field && uint64(relocation.VirtualAddress)+uint64(relocationWidth) >= uint64(field)+uint64(width) {
			return true
		}
	}
	return false
}

func writeRelative(data []byte, field uint32, width uint8, displacement int64) error {
	if uint64(field)+uint64(width) > uint64(len(data)) {
		return errors.New("relative field is out of bounds")
	}
	switch width {
	case 1:
		if displacement < math.MinInt8 || displacement > math.MaxInt8 {
			return ErrBranchOutOfRange
		}
		data[field] = byte(int8(displacement))
	case 4:
		if displacement < math.MinInt32 || displacement > math.MaxInt32 {
			return ErrBranchOutOfRange
		}
		binary.LittleEndian.PutUint32(data[field:field+4], uint32(int32(displacement)))
	default:
		return fmt.Errorf("unsupported relative width %d", width)
	}
	return nil
}

func validateUnwind(plan Plan, object *coff.Object, layouts map[*coff.Section]*sectionLayout, resolved map[*coff.Relocation]*coff.Symbol) error {
	if object.Machine != coff.MachineAMD64 {
		return nil
	}
	modifiedText, structuralText := false, false
	for section, layout := range layouts {
		if section.GroupName() == ".text" {
			modifiedText = modifiedText || layout.modified
			structuralText = structuralText || layout.structural
		}
	}
	if !modifiedText {
		return nil
	}
	for _, section := range object.Sections {
		if section == nil || !strings.HasPrefix(section.Name, ".pdata") {
			continue
		}
		if !plan.Unwind {
			return &UnwindError{Section: section.Name, Reason: "ised edits require unwind-aware planning"}
		}
		if !structuralText {
			continue
		}
		if len(section.Data)%12 != 0 {
			return &UnwindError{Section: section.Name, Reason: "data is not a sequence of 12-byte RUNTIME_FUNCTION records"}
		}
		for record := 0; record < len(section.Data); record += 12 {
			for _, field := range []uint32{uint32(record), uint32(record + 4)} {
				covered := false
				for _, relocation := range section.Relocations {
					if relocation.VirtualAddress != field {
						continue
					}
					symbol := resolved[relocation]
					if symbol != nil && symbol.Section != nil && symbol.Section.GroupName() == ".text" && layouts[symbol.Section] != nil {
						covered = true
						break
					}
				}
				if !covered {
					return &UnwindError{Section: section.Name, Offset: field, Reason: "runtime-function boundary lacks a relocation to the rewritten text section"}
				}
			}
		}
	}
	return nil
}

func prepareRebasedAddends(object *coff.Object, layouts map[*coff.Section]*sectionLayout, symbolValues map[*coff.Symbol]uint32, relocationValues map[*coff.Relocation]uint32, resolved map[*coff.Relocation]*coff.Symbol, data map[*coff.Section][]byte) error {
	for _, section := range object.Sections {
		for _, relocation := range section.Relocations {
			symbol := resolved[relocation]
			targetLayout := layouts[symbol.Section]
			if targetLayout == nil {
				continue
			}
			width, err := coffRelocationWidth(object.Machine, relocation.Type)
			if err != nil {
				return &BoundaryError{Section: section.Name, Offset: relocation.VirtualAddress, Feature: "relocation addend width", Err: errors.Join(ErrSemanticDetailUnavailable, err)}
			}
			sourceData := section.Data
			if sourceLayout := layouts[section]; sourceLayout != nil {
				sourceData = sourceLayout.oldData
			}
			addend, err := readAddend(sourceData, relocation.VirtualAddress, width)
			if err != nil {
				return fmt.Errorf("%w: read %s relocation %#x addend: %v", ErrInvalidObject, section.Name, relocation.VirtualAddress, err)
			}
			oldTarget := int64(symbol.Value) + addend
			if oldTarget < 0 || oldTarget > int64(len(targetLayout.oldData)) {
				continue
			}
			mappedTarget, err := targetLayout.mapOffset(uint32(oldTarget))
			if err != nil {
				return &BoundaryError{Section: section.Name, Offset: relocation.VirtualAddress, Feature: "relocation target mapping", Err: errors.Join(ErrSemanticDetailUnavailable, err)}
			}
			mappedSymbol, ok := symbolValues[symbol]
			if !ok {
				return fmt.Errorf("%w: target symbol %q was not rebased", ErrInvalidObject, symbol.Name)
			}
			output := data[section]
			if output == nil {
				output = append([]byte(nil), section.Data...)
				data[section] = output
			}
			if err := writeAddend(output, relocationValues[relocation], width, int64(mappedTarget)-int64(mappedSymbol)); err != nil {
				return fmt.Errorf("%w: write %s relocation %#x addend: %v", ErrInvalidObject, section.Name, relocation.VirtualAddress, err)
			}
		}
	}
	return nil
}

func coffRelocationWidth(machine coff.Machine, relocationType uint16) (uint32, error) {
	switch machine {
	case coff.MachineAMD64:
		switch relocationType {
		case coff.RelAMD64Addr64:
			return 8, nil
		case coff.RelAMD64Addr32NB, coff.RelAMD64Rel32, coff.RelAMD64Rel32_1, coff.RelAMD64Rel32_2, coff.RelAMD64Rel32_3, coff.RelAMD64Rel32_4, coff.RelAMD64Rel32_5:
			return 4, nil
		}
	case coff.MachineI386:
		if relocationType == coff.RelI386Dir32 || relocationType == coff.RelI386Rel32 {
			return 4, nil
		}
	}
	return 0, fmt.Errorf("unsupported relocation type %#x for %s", relocationType, machine)
}

func readAddend(data []byte, offset, width uint32) (int64, error) {
	if uint64(offset)+uint64(width) > uint64(len(data)) {
		return 0, errors.New("addend field is out of bounds")
	}
	if width == 4 {
		return int64(int32(binary.LittleEndian.Uint32(data[offset : offset+4]))), nil
	}
	if width == 8 {
		return int64(binary.LittleEndian.Uint64(data[offset : offset+8])), nil
	}
	return 0, fmt.Errorf("unsupported addend width %d", width)
}

func writeAddend(data []byte, offset, width uint32, value int64) error {
	if uint64(offset)+uint64(width) > uint64(len(data)) {
		return errors.New("addend field is out of bounds")
	}
	if width == 4 {
		if value < math.MinInt32 || value > math.MaxUint32 {
			return errors.New("addend does not fit 32 bits")
		}
		binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(value))
		return nil
	}
	if width == 8 {
		binary.LittleEndian.PutUint64(data[offset:offset+8], uint64(value))
		return nil
	}
	return fmt.Errorf("unsupported addend width %d", width)
}

// parentSection is used only to restore a nil relocation parent at commit.
func parentSection(object *coff.Object, target *coff.Relocation) *coff.Section {
	for _, section := range object.Sections {
		for _, relocation := range section.Relocations {
			if relocation == target {
				return section
			}
		}
	}
	return nil
}
