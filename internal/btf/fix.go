// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package btf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/imports"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

// EasyPICOptions selects the two upstream easy-PIC passes. Empty helper names
// disable their corresponding pass. Passes run in field order, matching the
// order used by Crystal Palace's FixPIC pipeline.
type EasyPICOptions struct {
	GetBSS        string
	ReturnAddress string
}

// FixReport describes one or more easy-PIC rewrites.
type FixReport struct {
	RewrittenInstructions int
	RemovedRelocations    int
	RetainedRelocations   int
}

func (r *FixReport) add(other FixReport) {
	r.RewrittenInstructions += other.RewrittenInstructions
	r.RemovedRelocations += other.RemovedRelocations
	r.RetainedRelocations += other.RetainedRelocations
}

// A coff.Object has no synchronization primitive. Serializing these uncommon
// mutating passes makes calls on the same object race-free while retaining a
// simple API. Planning remains transactional: no object field changes until a
// complete pass, including branch repair, has validated.
var easyPICMu sync.Mutex

// ApplyEasyPICFixes applies enabled easy-PIC passes in upstream order. Prefer
// the single-pass functions when replaying multiple fixbss/fixptrs commands,
// because command order is observable.
func ApplyEasyPICFixes(ctx context.Context, object *coff.Object, options EasyPICOptions) (FixReport, error) {
	easyPICMu.Lock()
	defer easyPICMu.Unlock()

	snapshot := snapshotEasyPICObject(object)
	rollback := func(err error) (FixReport, error) {
		snapshot.restore()
		return FixReport{}, err
	}
	var report FixReport
	if options.GetBSS != "" {
		result, err := fixBSSReferences(ctx, object, options.GetBSS, 0)
		if err != nil {
			return rollback(err)
		}
		report.add(result)
	}
	if options.ReturnAddress != "" {
		result, err := fixX86References(ctx, object, options.ReturnAddress)
		if err != nil {
			return rollback(err)
		}
		report.add(result)
	}
	return report, nil
}

type easyPICSnapshot struct {
	sections    map[*coff.Section]sectionFixSnapshot
	symbols     map[*coff.Symbol]uint32
	relocations map[*coff.Relocation]relocationFixSnapshot
}

type sectionFixSnapshot struct {
	data        []byte
	size        uint32
	relocations []*coff.Relocation
}

type relocationFixSnapshot struct {
	section *coff.Section
	address uint32
}

func snapshotEasyPICObject(object *coff.Object) easyPICSnapshot {
	snapshot := easyPICSnapshot{
		sections:    make(map[*coff.Section]sectionFixSnapshot),
		symbols:     make(map[*coff.Symbol]uint32),
		relocations: make(map[*coff.Relocation]relocationFixSnapshot),
	}
	if object == nil {
		return snapshot
	}
	for _, symbol := range object.Symbols {
		if symbol != nil {
			snapshot.symbols[symbol] = symbol.Value
		}
	}
	for _, section := range object.Sections {
		if section == nil {
			continue
		}
		if section.Name == ".text" {
			snapshot.sections[section] = sectionFixSnapshot{
				data:        append([]byte(nil), section.Data...),
				size:        section.SizeOfRawData,
				relocations: append([]*coff.Relocation(nil), section.Relocations...),
			}
		}
		for _, relocation := range section.Relocations {
			if relocation == nil {
				continue
			}
			snapshot.relocations[relocation] = relocationFixSnapshot{section: relocation.Section, address: relocation.VirtualAddress}
			if relocation.Symbol != nil {
				snapshot.symbols[relocation.Symbol] = relocation.Symbol.Value
			}
		}
	}
	return snapshot
}

func (s easyPICSnapshot) restore() {
	for section, value := range s.sections {
		section.Data = value.data
		section.SizeOfRawData = value.size
		section.Relocations = value.relocations
	}
	for symbol, value := range s.symbols {
		symbol.Value = value
	}
	for relocation, value := range s.relocations {
		relocation.Section = value.section
		relocation.VirtualAddress = value.address
	}
}

// FixX86References translates non-import, non-BSS i386 absolute references
// through returnAddress, matching ExportObject.fixX86References. A pass is
// transactional. Reapplying it is idempotent: generated relocation sites are
// recognized and left alone.
func FixX86References(ctx context.Context, object *coff.Object, returnAddress string) (FixReport, error) {
	easyPICMu.Lock()
	defer easyPICMu.Unlock()
	return fixX86References(ctx, object, returnAddress)
}

// FixBSSReferences selects the architecture-specific BSS pass. Reapplying it
// is idempotent because successfully rewritten BSS relocations are removed.
func FixBSSReferences(ctx context.Context, object *coff.Object, getBSS string) (FixReport, error) {
	easyPICMu.Lock()
	defer easyPICMu.Unlock()
	return fixBSSReferences(ctx, object, getBSS, 0)
}

// FixBSSReferencesX86 applies the i386 BSS pass and rejects other machines.
func FixBSSReferencesX86(ctx context.Context, object *coff.Object, getBSS string) (FixReport, error) {
	easyPICMu.Lock()
	defer easyPICMu.Unlock()
	return fixBSSReferences(ctx, object, getBSS, coff.MachineI386)
}

// FixBSSReferencesX64 applies the AMD64 BSS pass and rejects other machines.
func FixBSSReferencesX64(ctx context.Context, object *coff.Object, getBSS string) (FixReport, error) {
	easyPICMu.Lock()
	defer easyPICMu.Unlock()
	return fixBSSReferences(ctx, object, getBSS, coff.MachineAMD64)
}

type fixPass uint8

const (
	passX86References fixPass = iota + 1
	passBSSX86
	passBSSX64
)

func (p fixPass) String() string {
	switch p {
	case passX86References:
		return "FixX86References"
	case passBSSX86:
		return "FixBSSReferencesX86"
	case passBSSX64:
		return "FixBSSReferencesX64"
	default:
		return "easy-PIC"
	}
}

func fixX86References(ctx context.Context, object *coff.Object, helperName string) (FixReport, error) {
	if object == nil {
		return FixReport{}, errors.New("btf: FixX86References: nil COFF object")
	}
	if object.Machine != coff.MachineI386 {
		return FixReport{}, fmt.Errorf("btf: FixX86References requires x86 object, got %s", object.Machine)
	}
	return applyFixPass(ctx, object, helperName, passX86References)
}

func fixBSSReferences(ctx context.Context, object *coff.Object, helperName string, required coff.Machine) (FixReport, error) {
	if object == nil {
		return FixReport{}, errors.New("btf: FixBSSReferences: nil COFF object")
	}
	if required != 0 && object.Machine != required {
		return FixReport{}, fmt.Errorf("btf: BSS fix requires %s object, got %s", required, object.Machine)
	}
	var pass fixPass
	switch object.Machine {
	case coff.MachineI386:
		pass = passBSSX86
	case coff.MachineAMD64:
		pass = passBSSX64
	default:
		return FixReport{}, fmt.Errorf("btf: BSS fix does not support %s", object.Machine)
	}
	if findSection(object, ".bss") == nil {
		return FixReport{}, errors.New("btf: BSS fix requires a .bss section")
	}
	return applyFixPass(ctx, object, helperName, pass)
}

type fixInstruction struct {
	oldStart              uint32
	oldEnd                uint32
	raw                   []byte
	mnemonic              string
	operands              string
	output                []byte
	calls                 []int
	oldReloc              []*coff.Relocation
	newReloc              []relativeRelocation
	targeted              bool
	generatedX86Reference bool
}

type relativeRelocation struct {
	relocation *coff.Relocation
	offset     int
}

type fixPlan struct {
	object       *coff.Object
	text         *coff.Section
	helper       *coff.Symbol
	pass         fixPass
	instructions []*fixInstruction
	report       FixReport
	boundaries   map[uint32]struct{}
}

func applyFixPass(ctx context.Context, object *coff.Object, helperName string, pass fixPass) (report FixReport, err error) {
	if ctx == nil {
		return FixReport{}, errors.New("btf: easy-PIC: nil context")
	}
	if err := ctx.Err(); err != nil {
		return FixReport{}, fmt.Errorf("btf: %s: %w", pass, err)
	}
	text := findSection(object, ".text")
	if text == nil {
		return FixReport{}, fmt.Errorf("btf: %s requires a .text section", pass)
	}
	helper, err := findFunction(object, helperName)
	if err != nil {
		return FixReport{}, fmt.Errorf("btf: %s helper: %w", pass, err)
	}
	if helper.Section != text {
		return FixReport{}, fmt.Errorf("btf: %s helper %q is not in .text", pass, helperName)
	}
	if helper.Value >= uint32(len(text.Data)) {
		return FixReport{}, fmt.Errorf("btf: %s helper %q at %#x is outside .text", pass, helperName, helper.Value)
	}

	mode := x86.Mode32
	if object.Machine == coff.MachineAMD64 {
		mode = x86.Mode64
	}
	decoder, err := x86.NewCapstone(ctx, mode)
	if err != nil {
		return FixReport{}, fmt.Errorf("btf: %s: %w", pass, err)
	}
	decoded, err := decoder.Disassemble(ctx, text.Data, 0)
	if err != nil {
		_ = decoder.Close(context.Background())
		return FixReport{}, fmt.Errorf("btf: %s disassemble .text: %w", pass, err)
	}
	if err := decoder.Close(context.Background()); err != nil {
		return FixReport{}, fmt.Errorf("btf: %s close decoder: %w", pass, err)
	}

	plan := &fixPlan{object: object, text: text, helper: helper, pass: pass, boundaries: map[uint32]struct{}{0: {}}}
	for _, instruction := range decoded {
		if instruction.Address > math.MaxUint32 || uint64(len(instruction.Bytes)) > math.MaxUint32-instruction.Address {
			return FixReport{}, fmt.Errorf("btf: %s instruction address overflows .text", pass)
		}
		start := uint32(instruction.Address)
		end := start + uint32(len(instruction.Bytes))
		entry := &fixInstruction{oldStart: start, oldEnd: end, raw: instruction.Bytes, mnemonic: instruction.Mnemonic, operands: instruction.Operands, output: append([]byte(nil), instruction.Bytes...)}
		entry.generatedX86Reference = generatedX86ReferenceAt(text.Data, entry)
		plan.instructions = append(plan.instructions, entry)
		plan.boundaries[end] = struct{}{}
	}
	if len(decoded) == 0 && len(text.Data) != 0 {
		return FixReport{}, fmt.Errorf("btf: %s decoded no instructions from non-empty .text", pass)
	}

	for index, relocation := range text.Relocations {
		if relocation == nil {
			return FixReport{}, fmt.Errorf("btf: %s: .text relocation %d is nil", pass, index)
		}
		if relocation.Section != nil && relocation.Section != text {
			return FixReport{}, fmt.Errorf("btf: %s: .text relocation %d has foreign parent", pass, index)
		}
		if relocation.Symbol != nil && relocation.SymbolName != "" && relocation.SymbolName != relocation.Symbol.Name {
			return FixReport{}, fmt.Errorf("btf: %s: .text relocation %d names %q but points to %q", pass, index, relocation.SymbolName, relocation.Symbol.Name)
		}
		if relocation.Symbol != nil && relocation.Symbol.Section != nil && !containsSection(object, relocation.Symbol.Section) {
			return FixReport{}, fmt.Errorf("btf: %s: .text relocation %d points to symbol %q in a foreign section", pass, index, relocation.Symbol.Name)
		}
		entry := instructionAt(plan.instructions, relocation.VirtualAddress)
		if entry == nil || uint64(relocation.VirtualAddress)+4 > uint64(entry.oldEnd) {
			return FixReport{}, fmt.Errorf("btf: %s: relocation %#x is not a four-byte field inside one instruction", pass, relocation.VirtualAddress)
		}
		entry.oldReloc = append(entry.oldReloc, relocation)
	}

	for _, entry := range plan.instructions {
		var target *coff.Relocation
		for _, relocation := range entry.oldReloc {
			if passTargetsRelocation(pass, relocation, entry) {
				if target != nil {
					return FixReport{}, fmt.Errorf("btf: %s: instruction %#x has multiple target relocations", pass, entry.oldStart)
				}
				target = relocation
			}
		}
		if target == nil {
			for _, relocation := range entry.oldReloc {
				entry.newReloc = append(entry.newReloc, relativeRelocation{relocation: relocation, offset: int(relocation.VirtualAddress - entry.oldStart)})
			}
			continue
		}
		if len(entry.oldReloc) != 1 {
			return FixReport{}, fmt.Errorf("btf: %s: targeted instruction %#x also contains another relocation", pass, entry.oldStart)
		}
		if containingFunction(object, entry.oldStart) == nil {
			return FixReport{}, fmt.Errorf("btf: %s: relocated instruction %#x is not inside a function", pass, entry.oldStart)
		}
		if flagsLiveAfter(plan.instructions, entry, object) {
			return FixReport{}, fmt.Errorf("btf: %s: transforming instruction %#x may corrupt live flags", pass, entry.oldStart)
		}
		result, transformErr := transformEasyPIC(plan, entry, target)
		if transformErr != nil {
			return FixReport{}, transformErr
		}
		entry.output = result.bytes
		entry.calls = result.calls
		entry.targeted = true
		if result.relocationOffset >= 0 {
			entry.newReloc = append(entry.newReloc, relativeRelocation{relocation: target, offset: result.relocationOffset})
			plan.report.RetainedRelocations++
		} else {
			plan.report.RemovedRelocations++
		}
		plan.report.RewrittenInstructions++
	}
	if plan.report.RewrittenInstructions == 0 {
		return plan.report, nil
	}
	if err := ctx.Err(); err != nil {
		return FixReport{}, fmt.Errorf("btf: %s: %w", pass, err)
	}

	if err := plan.finish(); err != nil {
		return FixReport{}, err
	}
	return plan.report, nil
}

func passTargetsRelocation(pass fixPass, relocation *coff.Relocation, instruction *fixInstruction) bool {
	switch pass {
	case passBSSX86, passBSSX64:
		return isBSSRelocation(relocation)
	case passX86References:
		if isBSSRelocation(relocation) {
			return false
		}
		if _, imported := imports.ParseSymbol(relocationName(relocation)); imported {
			return false
		}
		if instruction.generatedX86Reference && int(relocation.VirtualAddress-instruction.oldStart) == 1 {
			return false
		}
		// Crystal Palace deliberately leaves direct CALL rel32 references for
		// the normal linker, even when their symbol spelling is suspicious.
		return !(len(instruction.raw) == 5 && instruction.raw[0] == 0xe8)
	default:
		return false
	}
}

func relocationName(relocation *coff.Relocation) string {
	if relocation == nil {
		return ""
	}
	if relocation.SymbolName != "" {
		return relocation.SymbolName
	}
	if relocation.Symbol != nil {
		return relocation.Symbol.Name
	}
	return ""
}

func isBSSRelocation(relocation *coff.Relocation) bool {
	if relocation == nil {
		return false
	}
	if relocation.SymbolName == ".bss" {
		return true
	}
	symbol := relocation.Symbol
	return symbol != nil && symbol.Section != nil && (symbol.Section.Name == ".bss" || symbol.Section.OriginalName == ".bss")
}

func findSection(object *coff.Object, name string) *coff.Section {
	if object == nil {
		return nil
	}
	for _, section := range object.Sections {
		if section != nil && section.Name == name {
			return section
		}
	}
	return nil
}

func containsSection(object *coff.Object, target *coff.Section) bool {
	if object == nil || target == nil {
		return false
	}
	for _, section := range object.Sections {
		if section == target {
			return true
		}
	}
	return false
}

func findFunction(object *coff.Object, name string) (*coff.Symbol, error) {
	if name == "" {
		return nil, errors.New("name is empty")
	}
	var result *coff.Symbol
	for _, symbol := range object.Symbols {
		if symbol == nil || symbol.Name != name {
			continue
		}
		if result != nil {
			return nil, fmt.Errorf("symbol %q is duplicated", name)
		}
		result = symbol
	}
	if result == nil {
		return nil, fmt.Errorf("symbol %q does not exist", name)
	}
	if !result.IsFunction() {
		return nil, fmt.Errorf("symbol %q is not a function", name)
	}
	return result, nil
}

func instructionAt(instructions []*fixInstruction, offset uint32) *fixInstruction {
	index := sort.Search(len(instructions), func(index int) bool { return instructions[index].oldEnd > offset })
	if index == len(instructions) || offset < instructions[index].oldStart {
		return nil
	}
	return instructions[index]
}

func (p *fixPlan) finish() error {
	newStarts := make(map[uint32]uint32, len(p.instructions)+1)
	var size uint64
	for _, entry := range p.instructions {
		newStarts[entry.oldStart] = uint32(size)
		size += uint64(len(entry.output))
		if size > math.MaxUint32 || size > math.MaxInt32 {
			return fmt.Errorf("btf: %s: rewritten .text is too large", p.pass)
		}
	}
	newStarts[uint32(len(p.text.Data))] = uint32(size)

	mapOffset := func(old uint32) (uint32, error) {
		if value, ok := newStarts[old]; ok {
			return value, nil
		}
		entry := instructionAt(p.instructions, old)
		if entry == nil {
			return 0, fmt.Errorf("offset %#x is outside .text", old)
		}
		if entry.targeted {
			return 0, fmt.Errorf("offset %#x points inside rewritten instruction %#x", old, entry.oldStart)
		}
		return newStarts[entry.oldStart] + (old - entry.oldStart), nil
	}

	textSymbols := make(map[*coff.Symbol]struct{})
	for _, symbol := range p.object.Symbols {
		if symbol == nil {
			return fmt.Errorf("btf: %s: nil symbol", p.pass)
		}
		if symbol.Section == p.text {
			textSymbols[symbol] = struct{}{}
		}
	}
	for _, section := range p.object.Sections {
		if section == nil {
			return fmt.Errorf("btf: %s: nil section", p.pass)
		}
		for _, relocation := range section.Relocations {
			if relocation != nil && relocation.Symbol != nil && relocation.Symbol.Section == p.text {
				textSymbols[relocation.Symbol] = struct{}{}
			}
		}
	}
	newSymbolValues := make(map[*coff.Symbol]uint32, len(textSymbols))
	for symbol := range textSymbols {
		value, err := mapOffset(symbol.Value)
		if err != nil {
			return fmt.Errorf("btf: %s: symbol %q: %w", p.pass, symbol.Name, err)
		}
		newSymbolValues[symbol] = value
	}

	output := make([]byte, int(size))
	for _, entry := range p.instructions {
		copy(output[newStarts[entry.oldStart]:], entry.output)
	}
	for _, entry := range p.instructions {
		start := newStarts[entry.oldStart]
		for _, callOffset := range entry.calls {
			field := uint64(start) + uint64(callOffset)
			if field+4 > uint64(len(output)) {
				return fmt.Errorf("btf: %s: internal helper-call fixup is out of range", p.pass)
			}
			target := newSymbolValues[p.helper]
			displacement := int64(target) - int64(field+4)
			if displacement < math.MinInt32 || displacement > math.MaxInt32 {
				return fmt.Errorf("btf: %s: helper call is outside rel32 range", p.pass)
			}
			binary.LittleEndian.PutUint32(output[field:field+4], uint32(int32(displacement)))
		}
	}
	if err := repairRelativeBranches(p, output, newStarts, mapOffset); err != nil {
		return err
	}

	newRelocations := make([]*coff.Relocation, 0, len(p.text.Relocations)-p.report.RemovedRelocations)
	relocationValues := make(map[*coff.Relocation]uint32, cap(newRelocations))
	for _, entry := range p.instructions {
		start := newStarts[entry.oldStart]
		for _, relative := range entry.newReloc {
			if relative.offset < 0 || uint64(relative.offset)+4 > uint64(len(entry.output)) {
				return fmt.Errorf("btf: %s: generated relocation for %#x is out of range", p.pass, entry.oldStart)
			}
			if _, exists := relocationValues[relative.relocation]; exists {
				return fmt.Errorf("btf: %s: relocation pointer appears more than once", p.pass)
			}
			relocationValues[relative.relocation] = start + uint32(relative.offset)
			newRelocations = append(newRelocations, relative.relocation)
		}
	}

	// Commit only after every allocation, displacement, and model reference has
	// validated. Relocation identity is preserved for callers holding pointers.
	p.text.Data = output
	p.text.SizeOfRawData = uint32(len(output))
	p.text.Relocations = newRelocations
	for relocation, value := range relocationValues {
		relocation.Section = p.text
		relocation.VirtualAddress = value
	}
	for symbol, value := range newSymbolValues {
		symbol.Value = value
	}
	return nil
}

func repairRelativeBranches(p *fixPlan, output []byte, starts map[uint32]uint32, mapOffset func(uint32) (uint32, error)) error {
	for _, entry := range p.instructions {
		if entry.targeted || len(entry.oldReloc) != 0 {
			continue
		}
		fieldOffset, fieldSize, ok := relativeField(entry.raw)
		if !ok {
			if isDirectControlFlow(entry) {
				return fmt.Errorf("btf: %s: unsupported relative control-flow encoding at %#x", p.pass, entry.oldStart)
			}
			if strings.Contains(strings.ToLower(entry.operands), "rip") {
				return fmt.Errorf("btf: %s: unrelocated RIP-relative operand at %#x cannot be safely rebased", p.pass, entry.oldStart)
			}
			continue
		}
		var oldDisplacement int64
		if fieldSize == 1 {
			oldDisplacement = int64(int8(entry.raw[fieldOffset]))
		} else {
			oldDisplacement = int64(int32(binary.LittleEndian.Uint32(entry.raw[fieldOffset : fieldOffset+4])))
		}
		oldTarget64 := int64(entry.oldEnd) + oldDisplacement
		if oldTarget64 < 0 || oldTarget64 > int64(len(p.text.Data)) {
			return fmt.Errorf("btf: %s: relative branch %#x targets outside .text", p.pass, entry.oldStart)
		}
		oldTarget := uint32(oldTarget64)
		if _, boundary := p.boundaries[oldTarget]; !boundary {
			return fmt.Errorf("btf: %s: relative branch %#x targets non-instruction boundary %#x", p.pass, entry.oldStart, oldTarget)
		}
		newTarget, err := mapOffset(oldTarget)
		if err != nil {
			return fmt.Errorf("btf: %s: relative branch %#x: %w", p.pass, entry.oldStart, err)
		}
		newStart := starts[entry.oldStart]
		field := newStart + uint32(fieldOffset)
		newEnd := newStart + uint32(len(entry.output))
		displacement := int64(newTarget) - int64(newEnd)
		if fieldSize == 1 {
			if displacement < math.MinInt8 || displacement > math.MaxInt8 {
				return fmt.Errorf("btf: %s: short branch %#x overflows after rewrite", p.pass, entry.oldStart)
			}
			output[field] = byte(int8(displacement))
		} else {
			if displacement < math.MinInt32 || displacement > math.MaxInt32 {
				return fmt.Errorf("btf: %s: rel32 branch %#x overflows after rewrite", p.pass, entry.oldStart)
			}
			binary.LittleEndian.PutUint32(output[field:field+4], uint32(int32(displacement)))
		}
	}
	return nil
}

func isDirectControlFlow(instruction *fixInstruction) bool {
	if instruction == nil {
		return false
	}
	mnemonic := instruction.mnemonic
	if mnemonic != "call" && !strings.HasPrefix(mnemonic, "j") && !strings.HasPrefix(mnemonic, "loop") {
		return false
	}
	operands := strings.TrimSpace(strings.ToLower(instruction.operands))
	if operands == "" || strings.ContainsAny(operands, "[]") {
		return false
	}
	numeric := strings.TrimPrefix(strings.TrimPrefix(operands, "+"), "-")
	numeric = strings.TrimPrefix(numeric, "0x")
	if numeric == "" {
		return false
	}
	for _, value := range numeric {
		if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
			return false
		}
	}
	return true
}

func relativeField(raw []byte) (offset, size int, ok bool) {
	if len(raw) == 2 && (raw[0] == 0xeb || raw[0] >= 0x70 && raw[0] <= 0x7f || raw[0] >= 0xe0 && raw[0] <= 0xe3) {
		return 1, 1, true
	}
	if len(raw) == 5 && (raw[0] == 0xe8 || raw[0] == 0xe9) {
		return 1, 4, true
	}
	if len(raw) == 6 && raw[0] == 0x0f && raw[1] >= 0x80 && raw[1] <= 0x8f {
		return 2, 4, true
	}
	return 0, 0, false
}

// Without Iced's RFLAGS metadata, use a deliberately conservative liveness
// walk. Unknown instructions between a neutral rewrite and the next definite
// flags write are treated as live, and therefore rejected.
func flagsLiveAfter(instructions []*fixInstruction, current *fixInstruction, object *coff.Object) bool {
	index := sort.Search(len(instructions), func(index int) bool { return instructions[index].oldStart >= current.oldEnd })
	functionEnd := uint32(math.MaxUint32)
	if function := containingFunction(object, current.oldStart); function != nil {
		functionEnd = uint32(len(findSection(object, ".text").Data))
		for _, symbol := range object.Symbols {
			if symbol != nil && symbol.Section == function.Section && symbol.IsFunction() && symbol.Value > function.Value && symbol.Value < functionEnd {
				functionEnd = symbol.Value
			}
		}
	}
	for ; index < len(instructions) && instructions[index].oldStart < functionEnd; index++ {
		mnemonic := instructions[index].mnemonic
		if readsFlags(mnemonic) {
			return true
		}
		if writesFlagsOrEnds(mnemonic) {
			return false
		}
		if !neutralForFlags(mnemonic) {
			return true
		}
	}
	return false
}

func containingFunction(object *coff.Object, offset uint32) *coff.Symbol {
	var result *coff.Symbol
	text := findSection(object, ".text")
	for _, symbol := range object.Symbols {
		if symbol != nil && symbol.Section == text && symbol.IsFunction() && symbol.Value <= offset && (result == nil || symbol.Value > result.Value) {
			result = symbol
		}
	}
	return result
}

func readsFlags(mnemonic string) bool {
	return (strings.HasPrefix(mnemonic, "j") && mnemonic != "jmp") || strings.HasPrefix(mnemonic, "cmov") || strings.HasPrefix(mnemonic, "set") || mnemonic == "adc" || mnemonic == "sbb" || strings.HasPrefix(mnemonic, "loop")
}

func writesFlagsOrEnds(mnemonic string) bool {
	switch mnemonic {
	case "add", "sub", "cmp", "test", "and", "or", "xor", "inc", "dec", "neg", "mul", "imul", "div", "idiv", "shl", "shr", "sar", "rol", "ror", "call", "ret", "jmp", "int", "syscall", "ud2":
		return true
	default:
		return false
	}
}

func neutralForFlags(mnemonic string) bool {
	switch mnemonic {
	case "mov", "movzx", "movsx", "movsxd", "lea", "push", "pop", "nop", "xchg", "leave", "endbr32", "endbr64":
		return true
	default:
		return false
	}
}
