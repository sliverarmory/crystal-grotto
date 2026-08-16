// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package transfer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

const transferSymbol = "__transfer"

var applyMu sync.Mutex

// Apply transactionally expands all canonical x64 CALL rel32 relocations to
// __transfer. On x86 the operation is an intentional no-op, matching upstream.
// Object identity, section identity, symbol identity, and surviving relocation
// identity are preserved.
func Apply(ctx context.Context, object *coff.Object, options Options) (Report, error) {
	if ctx == nil {
		return Report{}, invalid("input validation", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("transfer: %w", err)
	}
	if object == nil {
		return Report{}, invalid("input validation", errors.New("nil COFF object"))
	}
	if object.Machine == coff.MachineI386 {
		return Report{}, nil
	}
	if object.Machine != coff.MachineAMD64 {
		return Report{}, invalid("machine validation", fmt.Errorf("unsupported machine %s", object.Machine))
	}
	if !hasTransferRelocation(object) {
		return noOpReport(object), nil
	}
	if options.Disassembler != nil && options.Factory != nil {
		return Report{}, invalid("decoder setup", errors.New("Disassembler and Factory are mutually exclusive"))
	}

	applyMu.Lock()
	defer applyMu.Unlock()

	plan, err := newPlan(ctx, object, options)
	if err != nil {
		return Report{}, err
	}
	if err := plan.finish(ctx); err != nil {
		return Report{}, err
	}
	return plan.report.Clone(), nil
}

func noOpReport(object *coff.Object) Report {
	for _, section := range object.Sections {
		if section != nil && section.Name == ".text" {
			return Report{BytesBefore: len(section.Data), BytesAfter: len(section.Data)}
		}
	}
	return Report{}
}

func hasTransferRelocation(object *coff.Object) bool {
	for _, section := range object.Sections {
		if section == nil || section.Name != ".text" {
			continue
		}
		for _, relocation := range section.Relocations {
			if relocation != nil && (relocation.SymbolName == transferSymbol || relocation.Symbol != nil && relocation.Symbol.Name == transferSymbol) {
				return true
			}
		}
	}
	return false
}

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
	cond   byte
}

type branchVariant uint8

const (
	branchRaw branchVariant = iota
	branchShort
	branchNear
)

type instructionRelocation struct {
	relocation *coff.Relocation
	symbol     *coff.Symbol
	offset     uint32
	width      uint32
}

type instruction struct {
	oldStart    uint32
	oldEnd      uint32
	raw         []byte
	mnemonic    string
	operands    string
	reference   relativeReference
	hasFlow     bool
	flowReloc   bool
	relocations []instructionRelocation

	replacement []byte
	removed     bool
	variant     branchVariant
	region      *codeRegion
}

type codeRegion struct {
	name         string
	start        uint32
	end          uint32
	isFunction   bool
	instructions []*instruction
	prologueEnd  int
	epilogue     []byte
}

type plan struct {
	object       *coff.Object
	text         *coff.Section
	regions      []*codeRegion
	instructions []*instruction
	labels       map[uint32]*coff.Symbol
	boundaries   map[uint32]struct{}
	resolved     map[*coff.Relocation]*coff.Symbol
	consumed     map[*coff.Relocation]struct{}
	report       Report
}

func newPlan(ctx context.Context, object *coff.Object, options Options) (*plan, error) {
	text, regions, labels, symbolsByName, err := validateModel(object)
	if err != nil {
		return nil, err
	}
	decoder := options.Disassembler
	owned := false
	if decoder == nil {
		factory := options.Factory
		if factory == nil {
			factory = func(ctx context.Context, mode x86.Mode) (x86.Disassembler, error) {
				return x86.NewCapstone(ctx, mode)
			}
		}
		decoder, err = factory(ctx, x86.Mode64)
		if err != nil {
			return nil, &stageError{stage: "open disassembler", err: err}
		}
		if decoder == nil {
			return nil, invalid("decoder setup", errors.New("factory returned nil disassembler"))
		}
		owned = true
	}
	decoded, decodeErr := decoder.Disassemble(ctx, append([]byte(nil), text.Data...), 0)
	var closeErr error
	if owned {
		closeErr = decoder.Close(context.WithoutCancel(ctx))
	}
	if decodeErr != nil {
		if closeErr != nil {
			decodeErr = errors.Join(decodeErr, closeErr)
		}
		return nil, &stageError{stage: "disassemble .text", err: decodeErr}
	}
	if closeErr != nil {
		return nil, &stageError{stage: "close disassembler", err: closeErr}
	}

	p := &plan{
		object: object, text: text, regions: regions, labels: labels,
		boundaries: map[uint32]struct{}{0: {}},
		resolved:   make(map[*coff.Relocation]*coff.Symbol),
		consumed:   make(map[*coff.Relocation]struct{}),
		report:     Report{BytesBefore: len(text.Data)},
	}
	var expected uint64
	for index, decodedInstruction := range decoded {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("transfer: %w", err)
		}
		if decodedInstruction.Address != expected || len(decodedInstruction.Bytes) == 0 {
			return nil, malformed("instruction validation", fmt.Errorf("instruction %d starts at %#x with %d bytes", index, decodedInstruction.Address, len(decodedInstruction.Bytes)))
		}
		end := expected + uint64(len(decodedInstruction.Bytes))
		if end > uint64(len(text.Data)) {
			return nil, malformed("instruction validation", fmt.Errorf("instruction %#x exceeds .text", expected))
		}
		if !bytes.Equal(decodedInstruction.Bytes, text.Data[expected:end]) {
			return nil, malformed("instruction validation", fmt.Errorf("instruction %#x bytes differ from .text", expected))
		}
		if strings.TrimSpace(decodedInstruction.Mnemonic) == "" {
			return nil, malformed("instruction validation", fmt.Errorf("instruction %#x has no mnemonic", expected))
		}
		entry := &instruction{
			oldStart: uint32(expected), oldEnd: uint32(end),
			raw:      append([]byte(nil), decodedInstruction.Bytes...),
			mnemonic: strings.ToLower(strings.TrimSpace(decodedInstruction.Mnemonic)),
			operands: strings.ToLower(strings.TrimSpace(decodedInstruction.Operands)),
		}
		entry.reference, entry.hasFlow = decodeRelative(entry.raw)
		p.instructions = append(p.instructions, entry)
		expected = end
		p.boundaries[uint32(end)] = struct{}{}
	}
	if expected != uint64(len(text.Data)) {
		return nil, malformed("instruction validation", fmt.Errorf("decoder consumed %d of %d bytes", expected, len(text.Data)))
	}
	for _, region := range regions {
		if _, ok := p.boundaries[region.start]; !ok {
			return nil, malformed("symbol validation", fmt.Errorf("code symbol %q at %#x is not on an instruction boundary", region.name, region.start))
		}
		if _, ok := p.boundaries[region.end]; !ok {
			return nil, malformed("symbol validation", fmt.Errorf("code region %q ends at non-instruction boundary %#x", region.name, region.end))
		}
		for _, entry := range p.instructions {
			if entry.oldStart >= region.start && entry.oldStart < region.end {
				entry.region = region
				region.instructions = append(region.instructions, entry)
			}
		}
		if len(region.instructions) == 0 && region.start != region.end {
			return nil, malformed("symbol validation", fmt.Errorf("code region %q contains no instructions", region.name))
		}
	}
	if err := p.associateRelocations(symbolsByName); err != nil {
		return nil, err
	}
	if err := p.analyzeTransfers(); err != nil {
		return nil, err
	}
	if err := p.validateControlFlow(); err != nil {
		return nil, err
	}
	if p.report.RewrittenCalls == 0 {
		return nil, malformed("transfer analysis", errors.New("no .text relocation resolved to __transfer"))
	}
	return p, nil
}

func validateModel(object *coff.Object) (*coff.Section, []*codeRegion, map[uint32]*coff.Symbol, map[string]*coff.Symbol, error) {
	var text *coff.Section
	sections := make(map[*coff.Section]struct{}, len(object.Sections))
	sectionNames := make(map[string]struct{}, len(object.Sections))
	for index, section := range object.Sections {
		if section == nil {
			return nil, nil, nil, nil, malformed("object validation", fmt.Errorf("section %d is nil", index))
		}
		if section.Name == "" {
			return nil, nil, nil, nil, malformed("object validation", errors.New("empty section name"))
		}
		if _, exists := sectionNames[section.Name]; exists {
			return nil, nil, nil, nil, malformed("object validation", fmt.Errorf("duplicate section %q", section.Name))
		}
		if section.Object != nil && section.Object != object {
			return nil, nil, nil, nil, malformed("object validation", fmt.Errorf("section %q belongs to another object", section.Name))
		}
		sections[section] = struct{}{}
		sectionNames[section.Name] = struct{}{}
		if section.Name == ".text" {
			text = section
		}
	}
	if text == nil {
		return nil, nil, nil, nil, malformed("object validation", errors.New("object has no .text section"))
	}
	if uint64(len(text.Data)) > math.MaxInt32 {
		return nil, nil, nil, nil, malformed("object validation", errors.New(".text exceeds the upstream signed 32-bit size limit"))
	}

	byStart := make(map[uint32]*codeRegion)
	labels := make(map[uint32]*coff.Symbol)
	symbolsByName := make(map[string]*coff.Symbol, len(object.Symbols))
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return nil, nil, nil, nil, malformed("object validation", fmt.Errorf("symbol %d is nil", index))
		}
		if symbol.Name == "" {
			return nil, nil, nil, nil, malformed("object validation", fmt.Errorf("symbol %d has an empty name", index))
		}
		if symbolsByName[symbol.Name] != nil {
			return nil, nil, nil, nil, malformed("object validation", fmt.Errorf("duplicate symbol %q", symbol.Name))
		}
		symbolsByName[symbol.Name] = symbol
		if symbol.Section != nil {
			if _, ok := sections[symbol.Section]; !ok {
				return nil, nil, nil, nil, malformed("object validation", fmt.Errorf("symbol %q belongs to a foreign section", symbol.Name))
			}
		}
		if symbol.Section == text && !symbol.IsFunction() && !symbol.IsGlobalVariable() && symbol.Type == 0 && symbol.Value > 0 {
			return nil, nil, nil, nil, malformed("symbol validation", fmt.Errorf("candidate non-function/non-code symbol %q at %#x", symbol.Name, symbol.Value))
		}
		if symbol.Section != text || !symbol.IsFunction() && !symbol.IsGlobalVariable() {
			continue
		}
		if uint64(symbol.Value) >= uint64(len(text.Data)) {
			return nil, nil, nil, nil, malformed("symbol validation", fmt.Errorf("symbol %q at %#x is outside .text", symbol.Name, symbol.Value))
		}
		if existing := byStart[symbol.Value]; existing != nil {
			return nil, nil, nil, nil, malformed("symbol validation", fmt.Errorf("code symbols %q and %q share .text offset %#x", existing.name, symbol.Name, symbol.Value))
		}
		region := &codeRegion{name: symbol.Name, start: symbol.Value, isFunction: symbol.IsFunction()}
		byStart[symbol.Value] = region
		labels[symbol.Value] = symbol
	}
	regions := make([]*codeRegion, 0, len(byStart))
	for _, region := range byStart {
		regions = append(regions, region)
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].start < regions[j].start })
	if len(text.Data) != 0 {
		if len(regions) == 0 {
			return nil, nil, nil, nil, malformed("symbol validation", errors.New("non-empty .text has no function or global-data symbols"))
		}
		if regions[0].start != 0 {
			return nil, nil, nil, nil, malformed("symbol validation", fmt.Errorf("first code symbol %q starts at %#x, want zero", regions[0].name, regions[0].start))
		}
	}
	for index, region := range regions {
		region.end = uint32(len(text.Data))
		if index+1 < len(regions) {
			region.end = regions[index+1].start
		}
	}
	return text, regions, labels, symbolsByName, nil
}

func (p *plan) associateRelocations(symbolsByName map[string]*coff.Symbol) error {
	symbolPointers := make(map[*coff.Symbol]struct{}, len(p.object.Symbols))
	for _, symbol := range p.object.Symbols {
		symbolPointers[symbol] = struct{}{}
	}
	for _, section := range p.object.Sections {
		for index, relocation := range section.Relocations {
			if relocation == nil {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %d is nil", section.Name, index))
			}
			if relocation.Section != nil && relocation.Section != section {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %d has a foreign parent", section.Name, index))
			}
			symbol := relocation.Symbol
			if symbol == nil && relocation.SymbolName != "" {
				symbol = symbolsByName[relocation.SymbolName]
			}
			if symbol == nil {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %d references missing symbol %q", section.Name, index, relocation.SymbolName))
			}
			if _, present := symbolPointers[symbol]; !present {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %d references symbol %q outside the object", section.Name, index, symbol.Name))
			}
			if relocation.SymbolName != "" && relocation.SymbolName != symbol.Name {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %d names %q but points to %q", section.Name, index, relocation.SymbolName, symbol.Name))
			}
			if symbol.Section != nil && !objectContainsSection(p.object, symbol.Section) {
				return malformed("relocation validation", fmt.Errorf("relocation references symbol %q in a foreign section", symbol.Name))
			}
			p.resolved[relocation] = symbol
			width, widthErr := relocationWidth(relocation.Type)
			if widthErr != nil {
				if section == p.text || symbol.Section == p.text {
					return malformed("relocation validation", fmt.Errorf("section %q relocation %d: %w", section.Name, index, widthErr))
				}
				continue
			}
			if uint64(relocation.VirtualAddress)+uint64(width) > uint64(len(section.Data)) {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %#x is out of bounds", section.Name, relocation.VirtualAddress))
			}
			if section != p.text {
				continue
			}
			entry := instructionAt(p.instructions, relocation.VirtualAddress)
			if entry == nil || uint64(relocation.VirtualAddress)+uint64(width) > uint64(entry.oldEnd) {
				return malformed("relocation validation", fmt.Errorf(".text relocation %#x is not wholly inside one instruction", relocation.VirtualAddress))
			}
			relative := instructionRelocation{relocation: relocation, symbol: symbol, offset: relocation.VirtualAddress - entry.oldStart, width: width}
			entry.relocations = append(entry.relocations, relative)
			if entry.hasFlow && int(relative.offset) == entry.reference.offset && int(width) == entry.reference.size {
				entry.flowReloc = true
			}
		}
	}
	return nil
}

func objectContainsSection(object *coff.Object, target *coff.Section) bool {
	for _, section := range object.Sections {
		if section == target {
			return true
		}
	}
	return false
}

func relocationWidth(kind uint16) (uint32, error) {
	if kind == coff.RelAMD64Addr64 {
		return 8, nil
	}
	if kind == coff.RelAMD64Addr32NB || kind >= coff.RelAMD64Rel32 && kind <= coff.RelAMD64Rel32_5 {
		return 4, nil
	}
	return 0, fmt.Errorf("unsupported x64 relocation type %#x", kind)
}

func instructionAt(instructions []*instruction, offset uint32) *instruction {
	index := sort.Search(len(instructions), func(index int) bool { return instructions[index].oldEnd > offset })
	if index == len(instructions) || offset < instructions[index].oldStart {
		return nil
	}
	return instructions[index]
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
		return relativeReference{kind: relativeConditional, offset: 1, size: 1, cond: raw[0] & 0x0f}, true
	case len(raw) == 6 && raw[0] == 0x0f && raw[1] >= 0x80 && raw[1] <= 0x8f:
		return relativeReference{kind: relativeConditional, offset: 2, size: 4, cond: raw[1] & 0x0f}, true
	case len(raw) == 2 && raw[0] >= 0xe0 && raw[0] <= 0xe3:
		return relativeReference{kind: relativeLoop, offset: 1, size: 1}, true
	default:
		return relativeReference{}, false
	}
}

func unsupportedRelativeEncoding(raw []byte) (string, bool) {
	position := 0
	for position < len(raw) {
		switch raw[position] {
		case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3:
			position++
			continue
		}
		if raw[position] >= 0x40 && raw[position] <= 0x4f && position+1 < len(raw) {
			position++
			continue
		}
		break
	}
	if position >= len(raw) {
		return "", false
	}
	opcode := raw[position]
	if opcode == 0xc7 && position+1 < len(raw) && raw[position+1] == 0xf8 {
		return "XBEGIN relative target requires unavailable Iced branch detail", true
	}
	if opcode == 0xe8 || opcode == 0xe9 || opcode == 0xeb || opcode >= 0x70 && opcode <= 0x7f || opcode >= 0xe0 && opcode <= 0xe3 {
		return "prefixed or non-canonical relative control flow requires unavailable Iced branch detail", true
	}
	if opcode == 0x0f && position+1 < len(raw) && raw[position+1] >= 0x80 && raw[position+1] <= 0x8f {
		return "prefixed or non-canonical relative control flow requires unavailable Iced branch detail", true
	}
	return "", false
}

func relativeTarget(entry *instruction) (int64, error) {
	reference := entry.reference
	if !entry.hasFlow || reference.offset < 0 || reference.size <= 0 || reference.offset+reference.size > len(entry.raw) {
		return 0, errors.New("malformed relative instruction")
	}
	var displacement int64
	if reference.size == 1 {
		displacement = int64(int8(entry.raw[reference.offset]))
	} else {
		displacement = int64(int32(binary.LittleEndian.Uint32(entry.raw[reference.offset : reference.offset+4])))
	}
	return int64(entry.oldEnd) + displacement, nil
}

func (p *plan) validateControlFlow() error {
	for _, entry := range p.instructions {
		if entry.region == nil || !entry.region.isFunction {
			continue
		}
		if reason, relative := unsupportedRelativeEncoding(entry.raw); relative && !entry.hasFlow {
			return flowError(entry, reason)
		}
		if isDirectControlFlow(entry) && !entry.hasFlow {
			return flowError(entry, "direct control-flow encoding is not a portable rel8/rel32 form")
		}
		if entry.hasFlow {
			validMetadata := entry.reference.kind == relativeCall && entry.mnemonic == "call" ||
				entry.reference.kind == relativeJump && entry.mnemonic == "jmp" ||
				entry.reference.kind == relativeConditional && strings.HasPrefix(entry.mnemonic, "j") && entry.mnemonic != "jmp" ||
				entry.reference.kind == relativeLoop && (strings.HasPrefix(entry.mnemonic, "loop") || strings.Contains(entry.mnemonic, "cxz"))
			if !validMetadata {
				return flowError(entry, "raw relative-control-flow opcode disagrees with decoder metadata")
			}
		}
		if !entry.hasFlow || entry.flowReloc || entry.replacement != nil {
			continue
		}
		target, err := relativeTarget(entry)
		if err != nil {
			return flowError(entry, err.Error())
		}
		if target < 0 || target >= int64(len(p.text.Data)) {
			return malformed("control-flow validation", fmt.Errorf("branch %#x targets outside .text", entry.oldStart))
		}
		if _, boundary := p.boundaries[uint32(target)]; !boundary {
			return malformed("control-flow validation", fmt.Errorf("branch %#x targets non-instruction boundary %#x", entry.oldStart, target))
		}
		if entry.reference.kind == relativeCall && p.labels[uint32(target)] == nil {
			return malformed("control-flow validation", fmt.Errorf("local call %#x has no code symbol at %#x", entry.oldStart, target))
		}
	}
	return nil
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
	if operands == "" || strings.ContainsAny(operands, "[]") || isRegisterOperand(operands) || strings.Contains(operands, ":") {
		return false
	}
	return true
}

func isRegisterOperand(operand string) bool {
	operand = strings.TrimSpace(strings.ToLower(operand))
	for _, register := range registerNames {
		if operand == register {
			return true
		}
	}
	return false
}

func flowError(entry *instruction, reason string) *FlowError {
	result := &FlowError{Reason: reason}
	if entry != nil {
		result.Offset = entry.oldStart
		result.Bytes = append([]byte(nil), entry.raw...)
		if entry.region != nil {
			result.Function = entry.region.name
		}
	}
	return result
}

var registerNames = []string{
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}

type prologueAction struct {
	register int
	add      []byte
}

func (p *plan) analyzeTransfers() error {
	reportIndexes := make(map[*codeRegion]int)
	for _, relocation := range p.text.Relocations {
		symbol := p.resolved[relocation]
		if symbol == nil || symbol.Name != transferSymbol {
			continue
		}
		entry := instructionAt(p.instructions, relocation.VirtualAddress)
		if entry == nil {
			return &CallError{Offset: relocation.VirtualAddress, Reason: "relocation is outside a decoded instruction"}
		}
		if entry.region == nil || !entry.region.isFunction {
			return callError(entry, "relocation is not inside a function")
		}
		if relocation.Type != coff.RelAMD64Rel32 || relocation.VirtualAddress != entry.oldStart+1 || len(entry.raw) != 5 || entry.raw[0] != 0xe8 || entry.mnemonic != "call" {
			return callError(entry, "expected canonical CALL rel32 with an IMAGE_REL_AMD64_REL32 relocation at +1")
		}
		if entry.replacement != nil {
			return callError(entry, "multiple __transfer relocations reference one instruction")
		}
		if len(entry.relocations) != 1 || entry.relocations[0].relocation != relocation {
			return callError(entry, "CALL __transfer contains an additional relocation")
		}
		if entry.region.epilogue == nil {
			epilogue, end, err := deriveEpilogue(entry.region)
			if err != nil {
				return err
			}
			entry.region.epilogue = epilogue
			entry.region.prologueEnd = end
		}
		callIndex := indexOfInstruction(entry.region.instructions, entry)
		if callIndex < 0 {
			return malformed("transfer analysis", fmt.Errorf("call %#x is absent from its function", entry.oldStart))
		}
		if err := validateStableStack(entry.region, callIndex); err != nil {
			return err
		}
		entry.replacement = append(append([]byte(nil), entry.region.epilogue...), 0xff, 0xe1)
		p.consumed[relocation] = struct{}{}
		p.report.RewrittenCalls++

		nextIndex := callIndex + 1
		if nextIndex < len(entry.region.instructions) {
			next := entry.region.instructions[nextIndex]
			if len(next.raw) == 1 && next.raw[0] == 0x90 && next.mnemonic == "nop" {
				if next.removed {
					return callError(entry, "following NOP was already consumed")
				}
				if len(next.relocations) != 0 {
					return callError(entry, "following NOP carries a relocation")
				}
				next.removed = true
				p.report.ConsumedNOPs++
			}
		}
		reportIndex, exists := reportIndexes[entry.region]
		if !exists {
			reportIndex = len(p.report.Functions)
			reportIndexes[entry.region] = reportIndex
			p.report.Functions = append(p.report.Functions, FunctionReport{Name: entry.region.name, Epilogue: append([]byte(nil), entry.region.epilogue...)})
		}
		report := &p.report.Functions[reportIndex]
		report.Calls++
		report.CallOffsets = append(report.CallOffsets, entry.oldStart)
	}
	return nil
}

func indexOfInstruction(instructions []*instruction, target *instruction) int {
	for index, entry := range instructions {
		if entry == target {
			return index
		}
	}
	return -1
}

func deriveEpilogue(region *codeRegion) ([]byte, int, error) {
	actions := make([]prologueAction, 0)
	end := 0
	for end < len(region.instructions) {
		entry := region.instructions[end]
		if register, ok := canonicalPush64(entry.raw); ok {
			if entry.mnemonic != "push" || strings.TrimSpace(entry.operands) != registerNames[register] {
				return nil, 0, prologueError(region, entry, "canonical PUSH r64 bytes disagree with decoder metadata")
			}
			actions = append(actions, prologueAction{register: register})
			end++
			continue
		}
		if add, ok := canonicalSubRSP(entry.raw); ok {
			if entry.mnemonic != "sub" || firstOperand(entry.operands) != "rsp" {
				return nil, 0, prologueError(region, entry, "canonical SUB RSP bytes disagree with decoder metadata")
			}
			actions = append(actions, prologueAction{register: -1, add: add})
			end++
			continue
		}
		if entry.mnemonic == "push" || entry.mnemonic == "sub" && firstOperand(entry.operands) == "rsp" {
			return nil, 0, prologueError(region, entry, "prologue form is outside canonical PUSH r64/SUB RSP encodings")
		}
		break
	}
	epilogue := make([]byte, 0, len(actions)*4)
	for index := len(actions) - 1; index >= 0; index-- {
		action := actions[index]
		if action.register < 0 {
			epilogue = append(epilogue, action.add...)
			continue
		}
		if isNonvolatile(action.register) {
			epilogue = append(epilogue, encodePop64(action.register)...)
		} else {
			epilogue = append(epilogue, 0x48, 0x83, 0xc4, 0x08)
		}
	}
	return epilogue, end, nil
}

func canonicalPush64(raw []byte) (int, bool) {
	if len(raw) == 1 && raw[0] >= 0x50 && raw[0] <= 0x57 {
		return int(raw[0] - 0x50), true
	}
	if len(raw) == 2 && raw[0] == 0x41 && raw[1] >= 0x50 && raw[1] <= 0x57 {
		return 8 + int(raw[1]-0x50), true
	}
	return 0, false
}

func canonicalSubRSP(raw []byte) ([]byte, bool) {
	if len(raw) == 4 && raw[0] == 0x48 && raw[1] == 0x83 && raw[2] == 0xec {
		return []byte{0x48, 0x83, 0xc4, raw[3]}, true
	}
	if len(raw) == 7 && raw[0] == 0x48 && raw[1] == 0x81 && raw[2] == 0xec {
		value := int64(int32(binary.LittleEndian.Uint32(raw[3:7])))
		if value >= math.MinInt8 && value <= math.MaxInt8 {
			return []byte{0x48, 0x83, 0xc4, byte(int8(value))}, true
		}
		result := []byte{0x48, 0x81, 0xc4, 0, 0, 0, 0}
		copy(result[3:], raw[3:7])
		return result, true
	}
	return nil, false
}

func encodePop64(register int) []byte {
	if register < 8 {
		return []byte{0x58 + byte(register)}
	}
	return []byte{0x41, 0x58 + byte(register-8)}
}

func isNonvolatile(register int) bool {
	switch register {
	case 3, 5, 6, 7, 12, 13, 14, 15:
		return true
	default:
		return false
	}
}

func validateStableStack(region *codeRegion, callIndex int) error {
	for index := region.prologueEnd; index < callIndex; index++ {
		entry := region.instructions[index]
		if reason := unsupportedStackMutation(entry); reason != "" {
			return prologueError(region, entry, reason)
		}
	}
	return nil
}

func unsupportedStackMutation(entry *instruction) string {
	mnemonic := entry.mnemonic
	if strings.HasPrefix(mnemonic, "push") || strings.HasPrefix(mnemonic, "pop") || mnemonic == "enter" || mnemonic == "leave" {
		return "stack mutation after the recognized prologue makes the transfer epilogue path-dependent"
	}
	first := firstOperand(entry.operands)
	if first == "rsp" {
		switch mnemonic {
		case "add", "sub", "mov", "lea", "and", "or", "xor", "adc", "sbb", "inc", "dec", "neg", "not", "xchg":
			return "RSP is modified after the recognized prologue"
		}
	}
	if mnemonic == "xchg" && containsOperand(entry.operands, "rsp") {
		return "RSP is exchanged after the recognized prologue"
	}
	operands := splitOperands(entry.operands)
	if len(operands) >= 2 && strings.Contains(operands[0], "[") && containsToken(operands[0], "rsp") && isSavedNonvolatile(strings.TrimSpace(operands[1])) {
		return "nonvolatile register is saved to the stack outside TransferCall's PUSH model"
	}
	return ""
}

func firstOperand(operands string) string {
	parts := splitOperands(operands)
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func splitOperands(operands string) []string {
	if strings.TrimSpace(operands) == "" {
		return nil
	}
	return strings.Split(operands, ",")
}

func containsOperand(operands, operand string) bool {
	for _, candidate := range splitOperands(operands) {
		if strings.TrimSpace(candidate) == operand {
			return true
		}
	}
	return false
}

func containsToken(value, token string) bool {
	for _, candidate := range strings.FieldsFunc(strings.ToLower(value), func(character rune) bool {
		return !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_')
	}) {
		if candidate == token {
			return true
		}
	}
	return false
}

func isSavedNonvolatile(operand string) bool {
	switch operand {
	case "rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15",
		"xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15":
		return true
	default:
		return false
	}
}

func prologueError(region *codeRegion, entry *instruction, reason string) *PrologueError {
	result := &PrologueError{Function: region.name, Reason: reason}
	if entry != nil {
		result.Offset = entry.oldStart
		result.Bytes = append([]byte(nil), entry.raw...)
	}
	return result
}

func callError(entry *instruction, reason string) *CallError {
	result := &CallError{Reason: reason}
	if entry != nil {
		result.Offset = entry.oldStart
		result.Bytes = append([]byte(nil), entry.raw...)
		if entry.region != nil {
			result.Function = entry.region.name
		}
	}
	return result
}
