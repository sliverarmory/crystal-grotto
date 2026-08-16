// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

// Package mutate implements Crystal Palace's +mutate constant-blinding pass.
package mutate

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

// Options controls one +mutate pass. Magic contains the configured 32-bit
// diffuser pool. Random supplies Java nextInt()-equivalent values as four
// big-endian bytes per draw. When Magic is empty, each random value is itself
// the diffuser. Seed selects a deterministic java.util.Random-compatible
// stream and is mutually exclusive with Random.
type Options struct {
	Magic  []uint32
	Random io.Reader
	Seed   *int64
}

// Report describes the observable work performed by Apply. A relocation or a
// live-flags region makes an otherwise eligible instruction ineligible, just
// as it does in Crystal Palace.
type Report struct {
	MutatedInstructions int
	SkippedRelocations  int
	SkippedDangerous    int
	RandomDraws         int
}

// Apply transactionally applies one upstream-compatible +mutate pass to
// object. The COFF model is changed only after decoding, random selection,
// encoding, symbol rebasing, relocation rebasing, and branch repair all
// succeed. Random input can be consumed on an error. Like the upstream pass,
// Apply is not idempotent: a later pass can blind constants emitted by an
// earlier pass.
func Apply(ctx context.Context, object *coff.Object, options Options) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("mutate: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("mutate: %w", err)
	}
	if object == nil {
		return Report{}, errors.New("mutate: nil COFF object")
	}
	if options.Random != nil && options.Seed != nil {
		return Report{}, errors.New("mutate: Random and Seed are mutually exclusive")
	}

	// A COFF object is a pointer-rich mutable graph with no internal locking.
	// Serialize passes so concurrent calls on the same graph remain race-free.
	applyMu.Lock()
	defer applyMu.Unlock()

	plan, err := newPlan(ctx, object, options)
	if err != nil {
		return Report{}, err
	}
	if plan.report.MutatedInstructions == 0 {
		return plan.report, nil
	}
	if err := plan.finish(ctx); err != nil {
		return Report{}, err
	}
	return plan.report, nil
}

var applyMu sync.Mutex

type mutationPlan struct {
	object       *coff.Object
	text         *coff.Section
	instructions []*instruction
	boundaries   map[uint32]struct{}
	report       Report
}

type instruction struct {
	oldStart uint32
	oldEnd   uint32
	raw      []byte
	output   []byte
	mnemonic string
	operands string
	relocs   []instructionRelocation
	mutated  bool
	expanded branchExpansion
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
	start      uint32
	isFunction bool
	name       string
}

func newPlan(ctx context.Context, object *coff.Object, options Options) (*mutationPlan, error) {
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return nil, fmt.Errorf("mutate: unsupported machine %s", object.Machine)
	}
	text, regions, err := validateModel(object)
	if err != nil {
		return nil, err
	}
	mode := x86.Mode32
	if object.Machine == coff.MachineAMD64 {
		mode = x86.Mode64
	}
	decoder, err := x86.NewCapstone(ctx, mode)
	if err != nil {
		return nil, fmt.Errorf("mutate: open disassembler: %w", err)
	}
	decoded, decodeErr := decoder.Disassemble(ctx, text.Data, 0)
	closeErr := decoder.Close(context.Background())
	if decodeErr != nil {
		return nil, fmt.Errorf("mutate: disassemble .text: %w", decodeErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("mutate: close disassembler: %w", closeErr)
	}

	plan := &mutationPlan{
		object:     object,
		text:       text,
		boundaries: map[uint32]struct{}{0: {}},
	}
	for _, decodedInstruction := range decoded {
		if decodedInstruction.Address > math.MaxUint32 || uint64(len(decodedInstruction.Bytes)) > math.MaxUint32-decodedInstruction.Address {
			return nil, errors.New("mutate: instruction address overflows .text")
		}
		start := uint32(decodedInstruction.Address)
		end := start + uint32(len(decodedInstruction.Bytes))
		plan.instructions = append(plan.instructions, &instruction{
			oldStart: start,
			oldEnd:   end,
			raw:      append([]byte(nil), decodedInstruction.Bytes...),
			output:   append([]byte(nil), decodedInstruction.Bytes...),
			mnemonic: strings.ToLower(decodedInstruction.Mnemonic),
			operands: strings.ToLower(decodedInstruction.Operands),
		})
		plan.boundaries[end] = struct{}{}
	}
	if len(decoded) == 0 && len(text.Data) != 0 {
		return nil, errors.New("mutate: disassembler returned no instructions for non-empty .text")
	}
	for _, region := range regions {
		if _, ok := plan.boundaries[region.start]; !ok {
			return nil, fmt.Errorf("mutate: code symbol %q at %#x is not on an instruction boundary", region.name, region.start)
		}
	}
	if err := plan.associateRelocations(); err != nil {
		return nil, err
	}

	random, err := newInt32Random(options)
	if err != nil {
		return nil, err
	}
	for index, entry := range plan.instructions {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("mutate: %w", err)
		}
		if !regionIsFunction(regions, entry.oldStart) {
			continue
		}
		candidate, eligible, err := decodeCandidate(entry.raw, object.Machine)
		if err != nil {
			return nil, fmt.Errorf("mutate: instruction %#x: %w", entry.oldStart, err)
		}
		if !eligible {
			continue
		}
		if len(entry.relocs) != 0 {
			plan.report.SkippedRelocations++
			continue
		}
		if candidate.changesFlagsBeforeResult() {
			dangerous, err := flagsLiveAfter(plan.instructions, index, regions)
			if err != nil {
				return nil, fmt.Errorf("mutate: instruction %#x: %w", entry.oldStart, err)
			}
			if dangerous {
				plan.report.SkippedDangerous++
				continue
			}
		}
		output, draws, err := candidate.encode(random, options.Magic, object.Machine)
		if err != nil {
			return nil, fmt.Errorf("mutate: instruction %#x: %w", entry.oldStart, err)
		}
		if len(output) == 0 {
			return nil, fmt.Errorf("mutate: instruction %#x encoded to an empty sequence", entry.oldStart)
		}
		entry.output = output
		entry.mutated = true
		plan.report.MutatedInstructions++
		plan.report.RandomDraws += draws
	}
	return plan, nil
}

func validateModel(object *coff.Object) (*coff.Section, []functionRegion, error) {
	var text *coff.Section
	for index, section := range object.Sections {
		if section == nil {
			return nil, nil, fmt.Errorf("mutate: section %d is nil", index)
		}
		if section.Object != nil && section.Object != object {
			return nil, nil, fmt.Errorf("mutate: section %q belongs to another object", section.Name)
		}
		if section.Name == ".text" {
			if text != nil {
				return nil, nil, errors.New("mutate: duplicate .text section")
			}
			text = section
		}
	}
	if text == nil {
		return nil, nil, errors.New("mutate: object has no .text section")
	}
	if uint64(len(text.Data)) > math.MaxUint32 {
		return nil, nil, errors.New("mutate: .text exceeds the COFF 32-bit size limit")
	}

	regionsByStart := make(map[uint32]functionRegion)
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return nil, nil, fmt.Errorf("mutate: symbol %d is nil", index)
		}
		if symbol.Section != nil && !objectContainsSection(object, symbol.Section) {
			return nil, nil, fmt.Errorf("mutate: symbol %q belongs to a foreign section", symbol.Name)
		}
		if symbol.Section != text || (!symbol.IsFunction() && !symbol.IsGlobalVariable()) {
			continue
		}
		if symbol.Value > uint32(len(text.Data)) {
			return nil, nil, fmt.Errorf("mutate: symbol %q at %#x is outside .text", symbol.Name, symbol.Value)
		}
		region := functionRegion{start: symbol.Value, isFunction: symbol.IsFunction(), name: symbol.Name}
		previous, exists := regionsByStart[symbol.Value]
		if exists && previous.isFunction != region.isFunction {
			functionName, dataName := previous.name, region.name
			if region.isFunction {
				functionName, dataName = region.name, previous.name
			}
			return nil, nil, fmt.Errorf("mutate: function %q and data symbol %q share .text offset %#x", functionName, dataName, symbol.Value)
		}
		if !exists || region.name < previous.name {
			regionsByStart[symbol.Value] = region
		}
	}
	regions := make([]functionRegion, 0, len(regionsByStart))
	for _, region := range regionsByStart {
		regions = append(regions, region)
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].start < regions[j].start })
	if len(text.Data) != 0 && len(regions) == 0 {
		return nil, nil, errors.New("mutate: non-empty .text has no function or global-data symbols")
	}
	return text, regions, nil
}

func regionIsFunction(regions []functionRegion, offset uint32) bool {
	index := sort.Search(len(regions), func(index int) bool { return regions[index].start > offset }) - 1
	return index >= 0 && regions[index].isFunction
}

func regionEnd(regions []functionRegion, offset, textLength uint32) uint32 {
	index := sort.Search(len(regions), func(index int) bool { return regions[index].start > offset })
	if index < len(regions) {
		return regions[index].start
	}
	return textLength
}

func objectContainsSection(object *coff.Object, target *coff.Section) bool {
	for _, section := range object.Sections {
		if section == target {
			return true
		}
	}
	return false
}

func (p *mutationPlan) associateRelocations() error {
	for _, section := range p.object.Sections {
		for relocationIndex, relocation := range section.Relocations {
			if relocation == nil {
				return fmt.Errorf("mutate: section %q relocation %d is nil", section.Name, relocationIndex)
			}
			if relocation.Section != nil && relocation.Section != section {
				return fmt.Errorf("mutate: section %q relocation %d has a foreign parent", section.Name, relocationIndex)
			}
			if relocation.Symbol != nil {
				if relocation.SymbolName != "" && relocation.SymbolName != relocation.Symbol.Name {
					return fmt.Errorf("mutate: section %q relocation %d names %q but points to %q", section.Name, relocationIndex, relocation.SymbolName, relocation.Symbol.Name)
				}
				if relocation.Symbol.Section != nil && !objectContainsSection(p.object, relocation.Symbol.Section) {
					return fmt.Errorf("mutate: relocation references symbol %q in a foreign section", relocation.Symbol.Name)
				}
			}
			width, err := relocationWidth(p.object.Machine, relocation.Type)
			if err != nil {
				return fmt.Errorf("mutate: section %q relocation %d: %w", section.Name, relocationIndex, err)
			}
			if uint64(relocation.VirtualAddress)+uint64(width) > uint64(len(section.Data)) {
				return fmt.Errorf("mutate: section %q relocation %#x is out of bounds", section.Name, relocation.VirtualAddress)
			}
			if section != p.text {
				continue
			}
			entry := instructionAt(p.instructions, relocation.VirtualAddress)
			if entry == nil || uint64(relocation.VirtualAddress)+uint64(width) > uint64(entry.oldEnd) {
				return fmt.Errorf("mutate: .text relocation %#x is not wholly inside one instruction", relocation.VirtualAddress)
			}
			entry.relocs = append(entry.relocs, instructionRelocation{
				relocation: relocation,
				offset:     relocation.VirtualAddress - entry.oldStart,
			})
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

func (p *mutationPlan) finish(ctx context.Context) error {
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
		if entry.mutated || entry.expanded != branchUnchanged {
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
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("mutate: %w", err)
	}

	newRelocationValues := make(map[*coff.Relocation]uint32, len(p.text.Relocations))
	for _, entry := range p.instructions {
		start := starts[entry.oldStart]
		for _, relative := range entry.relocs {
			if relative.offset >= uint32(len(entry.output)) {
				return fmt.Errorf("mutate: relocation offset escaped instruction %#x", entry.oldStart)
			}
			newRelocationValues[relative.relocation] = start + relative.offset
		}
	}

	// Commit the complete plan at once. Relocation and symbol pointer identity
	// is intentionally retained for callers holding references to the model.
	p.text.Data = output
	p.text.SizeOfRawData = uint32(len(output))
	if p.text.VirtualSize != 0 {
		p.text.VirtualSize = uint32(len(output))
	}
	for relocation, value := range newRelocationValues {
		relocation.Section = p.text
		relocation.VirtualAddress = value
	}
	for symbol, value := range newSymbolValues {
		symbol.Value = value
	}
	return nil
}

func (p *mutationPlan) layout() (map[uint32]uint32, int, error) {
	starts := make(map[uint32]uint32, len(p.instructions)+1)
	var size uint64
	for _, entry := range p.instructions {
		starts[entry.oldStart] = uint32(size)
		size += uint64(len(entry.output))
		if size > math.MaxUint32 || size > uint64(math.MaxInt) {
			return nil, 0, errors.New("mutate: rewritten .text is too large")
		}
	}
	starts[uint32(len(p.text.Data))] = uint32(size)
	return starts, int(size), nil
}

func (p *mutationPlan) rebasedSymbols(mapOffset func(uint32) (uint32, error)) (map[*coff.Symbol]uint32, error) {
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
			return nil, fmt.Errorf("mutate: symbol %q: %w", symbol.Name, err)
		}
		values[symbol] = value
	}
	return values, nil
}

type int32Random interface {
	nextInt32() (int32, error)
}

type readerRandom struct{ reader io.Reader }

func (r readerRandom) nextInt32() (int32, error) {
	var data [4]byte
	if _, err := io.ReadFull(r.reader, data[:]); err != nil {
		return 0, fmt.Errorf("read randomness: %w", err)
	}
	return int32(binary.BigEndian.Uint32(data[:])), nil
}

// javaRandom implements java.util.Random's 48-bit generator. Crystal Palace
// uses SecureRandom in production; the Java LCG is exposed here solely as a
// stable, seedable test and reproducibility stream.
type javaRandom struct{ state uint64 }

const (
	javaRandomMultiplier = uint64(0x5deece66d)
	javaRandomAddend     = uint64(0xb)
	javaRandomMask       = uint64(1<<48) - 1
)

func newJavaRandom(seed int64) *javaRandom {
	return &javaRandom{state: (uint64(seed) ^ javaRandomMultiplier) & javaRandomMask}
}

func (r *javaRandom) nextInt32() (int32, error) {
	r.state = (r.state*javaRandomMultiplier + javaRandomAddend) & javaRandomMask
	return int32(uint32(r.state >> 16)), nil
}

func newInt32Random(options Options) (int32Random, error) {
	if options.Seed != nil {
		return newJavaRandom(*options.Seed), nil
	}
	reader := options.Random
	if reader == nil {
		reader = cryptorand.Reader
	}
	return readerRandom{reader: reader}, nil
}
