// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package regdance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var applyMu sync.Mutex

// Apply transactionally applies one upstream-compatible +regdance pass to
// object. Randomness may be consumed on failure, but the COFF graph is changed
// only after every instruction, branch, symbol, relocation, and supported
// unwind reference has been rebuilt successfully. Like upstream, the pass is
// not idempotent: replaying it composes another permutation over the body.
func Apply(ctx context.Context, object *coff.Object, options Options) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("regdance: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("regdance: %w", err)
	}
	if object == nil {
		return Report{}, errors.New("regdance: nil COFF object")
	}
	random, err := newBoundedRandom(options)
	if err != nil {
		return Report{}, err
	}

	// COFF is a mutable pointer graph without internal synchronization.
	applyMu.Lock()
	defer applyMu.Unlock()

	plan, err := newDancePlan(ctx, object)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = plan.decoder.Close(context.Background()) }()

	for _, function := range plan.functions {
		if err := ctx.Err(); err != nil {
			return Report{}, fmt.Errorf("regdance: %w", err)
		}
		if !function.isFunction {
			continue
		}
		saved, err := analyzeSavedRegisters(plan, function)
		if err != nil {
			return Report{}, fmt.Errorf("regdance: function %q: %w", function.name, err)
		}
		if !saved.sane() {
			continue
		}
		plan.report.EligibleFunctions++
		exits, err := exitCount(plan, function)
		if err != nil {
			return Report{}, fmt.Errorf("regdance: function %q: %w", function.name, err)
		}
		if exits != 1 {
			continue
		}

		original := append([]Register(nil), saved.swappable...)
		permuted := append([]Register(nil), original...)
		draws, err := shuffle(permuted, random)
		plan.report.RandomDraws += draws
		if err != nil {
			return Report{}, fmt.Errorf("regdance: function %q shuffle: %w", function.name, err)
		}
		mapping := make(map[Register]Register, len(original))
		functionReport := FunctionReport{Name: function.name, Mapping: make([]Mapping, 0, len(original))}
		for index, source := range original {
			mapping[source] = permuted[index]
			functionReport.Mapping = append(functionReport.Mapping, Mapping{From: source, To: permuted[index]})
		}

		for _, entry := range function.instructions {
			if saved.isBookend(entry) {
				continue
			}
			expected, changed := replaceRegisters(entry.operands, mapping)
			if !changed {
				continue
			}
			output, err := plan.transformInstruction(ctx, function.name, entry, expected, mapping)
			if err != nil {
				return Report{}, err
			}
			entry.output = output
			entry.rewritten = true
			functionReport.ChangedInstructions++
			plan.report.ChangedInstructions++
			if plan.hasExistingUnwind && entry == saved.framePointer {
				return Report{}, &UnsupportedUnwindError{
					Function: function.name,
					Offset:   entry.oldStart,
					Reason:   "existing .xdata frame-register metadata would be stale after frame-pointer remapping",
				}
			}
		}
		plan.report.RemappedFunctions++
		plan.report.Functions = append(plan.report.Functions, functionReport)
	}

	if plan.report.ChangedInstructions == 0 {
		return plan.report, nil
	}
	if err := plan.finish(ctx); err != nil {
		return Report{}, err
	}
	return plan.report, nil
}

type dancePlan struct {
	object            *coff.Object
	text              *coff.Section
	decoder           *x86.Capstone
	instructions      []*instruction
	functions         []*functionRegion
	labels            map[uint32]*coff.Symbol
	boundaries        map[uint32]struct{}
	hasExistingUnwind bool
	report            Report
}

type instruction struct {
	oldStart    uint32
	oldEnd      uint32
	raw         []byte
	output      []byte
	mnemonic    string
	operands    string
	relocations []instructionRelocation
	rewritten   bool
	expanded    branchExpansion
}

type instructionRelocation struct {
	relocation *coff.Relocation
	offset     uint32
}

type branchExpansion uint8

const (
	branchUnchanged branchExpansion = iota
	branchNearJMP
	branchNearJCC
)

type functionRegion struct {
	name         string
	start        uint32
	end          uint32
	isFunction   bool
	instructions []*instruction
}

func newDancePlan(ctx context.Context, object *coff.Object) (*dancePlan, error) {
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return nil, fmt.Errorf("regdance: unsupported machine %s", object.Machine)
	}
	text, functions, labels, err := validateModel(object)
	if err != nil {
		return nil, err
	}
	mode := x86.Mode32
	if object.Machine == coff.MachineAMD64 {
		mode = x86.Mode64
	}
	decoder, err := x86.NewCapstone(ctx, mode)
	if err != nil {
		return nil, fmt.Errorf("regdance: open disassembler: %w", err)
	}
	decoded, err := decoder.Disassemble(ctx, text.Data, 0)
	if err != nil {
		_ = decoder.Close(context.Background())
		return nil, fmt.Errorf("regdance: disassemble .text: %w", err)
	}
	plan := &dancePlan{
		object:     object,
		text:       text,
		decoder:    decoder,
		functions:  functions,
		labels:     labels,
		boundaries: map[uint32]struct{}{0: {}},
	}
	for _, section := range object.Sections {
		if section != nil && (strings.HasPrefix(section.Name, ".pdata") || strings.HasPrefix(section.Name, ".xdata")) {
			plan.hasExistingUnwind = true
		}
	}
	for _, decodedInstruction := range decoded {
		if decodedInstruction.Address > math.MaxUint32 || uint64(len(decodedInstruction.Bytes)) > math.MaxUint32-decodedInstruction.Address {
			_ = decoder.Close(context.Background())
			return nil, errors.New("regdance: instruction address overflows .text")
		}
		start := uint32(decodedInstruction.Address)
		end := start + uint32(len(decodedInstruction.Bytes))
		entry := &instruction{
			oldStart: start,
			oldEnd:   end,
			raw:      append([]byte(nil), decodedInstruction.Bytes...),
			output:   append([]byte(nil), decodedInstruction.Bytes...),
			mnemonic: strings.ToLower(decodedInstruction.Mnemonic),
			operands: normalizeOperands(decodedInstruction.Operands),
		}
		plan.instructions = append(plan.instructions, entry)
		plan.boundaries[end] = struct{}{}
	}
	for _, function := range functions {
		if _, ok := plan.boundaries[function.start]; !ok {
			_ = decoder.Close(context.Background())
			return nil, fmt.Errorf("regdance: code symbol %q at %#x is not on an instruction boundary", function.name, function.start)
		}
		if _, ok := plan.boundaries[function.end]; !ok {
			_ = decoder.Close(context.Background())
			return nil, fmt.Errorf("regdance: code region %q ends at non-instruction boundary %#x", function.name, function.end)
		}
		for _, entry := range plan.instructions {
			if entry.oldStart >= function.start && entry.oldStart < function.end {
				function.instructions = append(function.instructions, entry)
			}
		}
	}
	if err := plan.associateRelocations(); err != nil {
		_ = decoder.Close(context.Background())
		return nil, err
	}
	return plan, nil
}

func validateModel(object *coff.Object) (*coff.Section, []*functionRegion, map[uint32]*coff.Symbol, error) {
	var text *coff.Section
	for index, section := range object.Sections {
		if section == nil {
			return nil, nil, nil, fmt.Errorf("regdance: section %d is nil", index)
		}
		if section.Object != nil && section.Object != object {
			return nil, nil, nil, fmt.Errorf("regdance: section %q belongs to another object", section.Name)
		}
		if section.Name == ".text" {
			if text != nil {
				return nil, nil, nil, errors.New("regdance: duplicate .text section")
			}
			text = section
		}
	}
	if text == nil {
		return nil, nil, nil, errors.New("regdance: object has no .text section")
	}
	if uint64(len(text.Data)) > math.MaxUint32 {
		return nil, nil, nil, errors.New("regdance: .text exceeds the COFF 32-bit size limit")
	}

	byStart := make(map[uint32]*functionRegion)
	labels := make(map[uint32]*coff.Symbol)
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return nil, nil, nil, fmt.Errorf("regdance: symbol %d is nil", index)
		}
		if symbol.Section != nil && !objectContainsSection(object, symbol.Section) {
			return nil, nil, nil, fmt.Errorf("regdance: symbol %q belongs to a foreign section", symbol.Name)
		}
		if symbol.Section != text || (!symbol.IsFunction() && !symbol.IsGlobalVariable()) {
			continue
		}
		if symbol.Value > uint32(len(text.Data)) {
			return nil, nil, nil, fmt.Errorf("regdance: symbol %q at %#x is outside .text", symbol.Name, symbol.Value)
		}
		labels[symbol.Value] = symbol
		region := &functionRegion{name: symbol.Name, start: symbol.Value, isFunction: symbol.IsFunction()}
		if existing := byStart[symbol.Value]; existing != nil {
			if existing.isFunction != region.isFunction {
				return nil, nil, nil, fmt.Errorf("regdance: function/data symbols %q and %q share .text offset %#x", existing.name, region.name, region.start)
			}
			if region.name < existing.name {
				byStart[symbol.Value] = region
			}
			continue
		}
		byStart[symbol.Value] = region
	}
	regions := make([]*functionRegion, 0, len(byStart))
	for _, region := range byStart {
		regions = append(regions, region)
	}
	sortedFunctionRegions(regions)
	for index, region := range regions {
		region.end = uint32(len(text.Data))
		if index+1 < len(regions) {
			region.end = regions[index+1].start
		}
	}
	if len(text.Data) != 0 && len(regions) == 0 {
		return nil, nil, nil, errors.New("regdance: non-empty .text has no function or global-data symbols")
	}
	return text, regions, labels, nil
}

func objectContainsSection(object *coff.Object, target *coff.Section) bool {
	for _, section := range object.Sections {
		if section == target {
			return true
		}
	}
	return false
}

func (p *dancePlan) associateRelocations() error {
	symbols := make(map[*coff.Symbol]struct{}, len(p.object.Symbols))
	for _, symbol := range p.object.Symbols {
		symbols[symbol] = struct{}{}
	}
	for _, section := range p.object.Sections {
		for index, relocation := range section.Relocations {
			if relocation == nil {
				return fmt.Errorf("regdance: section %q relocation %d is nil", section.Name, index)
			}
			if relocation.Section != nil && relocation.Section != section {
				return fmt.Errorf("regdance: section %q relocation %d has a foreign parent", section.Name, index)
			}
			if relocation.Symbol == nil {
				return fmt.Errorf("regdance: section %q relocation %d references missing symbol %q", section.Name, index, relocation.SymbolName)
			}
			if _, present := symbols[relocation.Symbol]; !present {
				return fmt.Errorf("regdance: section %q relocation %d references symbol %q outside the object", section.Name, index, relocation.Symbol.Name)
			}
			if relocation.SymbolName != "" && relocation.SymbolName != relocation.Symbol.Name {
				return fmt.Errorf("regdance: section %q relocation %d names %q but points to %q", section.Name, index, relocation.SymbolName, relocation.Symbol.Name)
			}
			if relocation.Symbol.Section != nil && !objectContainsSection(p.object, relocation.Symbol.Section) {
				return fmt.Errorf("regdance: relocation references symbol %q in a foreign section", relocation.Symbol.Name)
			}
			width, err := relocationWidth(p.object.Machine, relocation.Type)
			if err != nil {
				return fmt.Errorf("regdance: section %q relocation %d: %w", section.Name, index, err)
			}
			if uint64(relocation.VirtualAddress)+uint64(width) > uint64(len(section.Data)) {
				return fmt.Errorf("regdance: section %q relocation %#x is out of bounds", section.Name, relocation.VirtualAddress)
			}
			if section != p.text {
				continue
			}
			entry := instructionAt(p.instructions, relocation.VirtualAddress)
			if entry == nil || uint64(relocation.VirtualAddress)+uint64(width) > uint64(entry.oldEnd) {
				return fmt.Errorf("regdance: .text relocation %#x is not wholly inside one instruction", relocation.VirtualAddress)
			}
			entry.relocations = append(entry.relocations, instructionRelocation{relocation: relocation, offset: relocation.VirtualAddress - entry.oldStart})
		}
	}
	return nil
}

func relocationWidth(machine coff.Machine, kind uint16) (uint32, error) {
	switch machine {
	case coff.MachineI386:
		if kind == coff.RelI386Dir32 || kind == coff.RelI386Rel32 {
			return 4, nil
		}
	case coff.MachineAMD64:
		if kind == coff.RelAMD64Addr64 {
			return 8, nil
		}
		if kind == coff.RelAMD64Addr32NB || kind >= coff.RelAMD64Rel32 && kind <= coff.RelAMD64Rel32_5 {
			return 4, nil
		}
	}
	return 0, fmt.Errorf("unsupported relocation type %#x for %s", kind, machine)
}

func instructionAt(instructions []*instruction, offset uint32) *instruction {
	index := sort.Search(len(instructions), func(index int) bool { return instructions[index].oldEnd > offset })
	if index == len(instructions) || offset < instructions[index].oldStart {
		return nil
	}
	return instructions[index]
}

func (p *dancePlan) transformInstruction(ctx context.Context, function string, entry *instruction, expected string, mapping map[Register]Register) ([]byte, error) {
	encoding, err := parseInstructionEncoding(entry.raw, p.object.Machine)
	if err != nil {
		return nil, unsupported(function, entry, err.Error())
	}
	fields := encoding.candidateFields(mapping)
	if len(fields) == 0 {
		return nil, unsupported(function, entry, "no provable encoded GPR field matches Capstone operands")
	}
	if len(fields) > 8 {
		return nil, unsupported(function, entry, "too many ambiguous encoded register fields")
	}
	type match struct{ bytes []byte }
	var matches []match
	for selected := uint(1); selected < 1<<len(fields); selected++ {
		variant, err := encoding.rewrite(fields, selected, mapping, expected)
		if err != nil {
			continue
		}
		decoded, err := p.decoder.Disassemble(ctx, variant, uint64(entry.oldStart))
		if err != nil || len(decoded) != 1 {
			continue
		}
		if strings.ToLower(decoded[0].Mnemonic) != entry.mnemonic || normalizeOperands(decoded[0].Operands) != normalizeOperands(expected) {
			continue
		}
		duplicate := false
		for _, existing := range matches {
			if bytes.Equal(existing.bytes, variant) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			matches = append(matches, match{bytes: variant})
		}
	}
	if len(matches) == 0 {
		return nil, unsupported(function, entry, "Capstone could not verify an equivalent register-substituted encoding")
	}
	sort.Slice(matches, func(i, j int) bool {
		if len(matches[i].bytes) != len(matches[j].bytes) {
			return len(matches[i].bytes) < len(matches[j].bytes)
		}
		return bytes.Compare(matches[i].bytes, matches[j].bytes) < 0
	})
	return append([]byte(nil), matches[0].bytes...), nil
}

func unsupported(function string, entry *instruction, reason string) *UnsupportedInstructionError {
	return &UnsupportedInstructionError{Function: function, Offset: entry.oldStart, Bytes: append([]byte(nil), entry.raw...), Reason: reason}
}
