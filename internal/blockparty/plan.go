// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package blockparty

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

var applyMu sync.Mutex

// Apply transactionally applies one upstream-compatible +blockparty pass.
// Randomness may be consumed on failure, but object is not changed until all
// branch, symbol, relocation, addend, and auxiliary-record repairs validate.
// Applying the pass again is intentionally observable and may choose a new
// permutation, matching upstream behavior.
func Apply(ctx context.Context, object *coff.Object, options Options) (Report, error) {
	if ctx == nil {
		return Report{}, invalid("input validation", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return Report{}, fmt.Errorf("blockparty: %w", err)
	}
	if object == nil {
		return Report{}, invalid("input validation", errors.New("nil COFF object"))
	}
	if options.Disassembler != nil && options.Factory != nil {
		return Report{}, invalid("decoder setup", errors.New("Disassembler and Factory are mutually exclusive"))
	}
	random, err := newBoundedRandom(options)
	if err != nil {
		return Report{}, err
	}

	applyMu.Lock()
	defer applyMu.Unlock()

	plan, err := newPlan(ctx, object, options)
	if err != nil {
		return Report{}, err
	}
	if err := plan.selectOrder(ctx, random); err != nil {
		return Report{}, err
	}
	if err := plan.finish(ctx); err != nil {
		return Report{}, err
	}
	return plan.report.Clone(), nil
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

	variant branchVariant
	removed bool
	region  *codeRegion
}

type branchVariant uint8

const (
	branchRaw branchVariant = iota
	branchShort
	branchNear
)

type codeRegion struct {
	name         string
	start        uint32
	end          uint32
	isFunction   bool
	instructions []*instruction
	blocks       []*basicBlock
	selected     []*basicBlock
}

type basicBlock struct {
	leader       uint32
	instructions []*instruction
	edgeTarget   uint32
	hasEdge      bool
}

type connector struct {
	after    *instruction
	target   uint32
	near     bool
	function string
}

type plan struct {
	object       *coff.Object
	text         *coff.Section
	regions      []*codeRegion
	instructions []*instruction
	labels       map[uint32]*coff.Symbol
	boundaries   map[uint32]struct{}
	resolved     map[*coff.Relocation]*coff.Symbol
	order        []*instruction
	connectors   map[*instruction]*connector
	report       Report
}

func newPlan(ctx context.Context, object *coff.Object, options Options) (*plan, error) {
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return nil, invalid("machine validation", fmt.Errorf("unsupported machine %s", object.Machine))
	}
	text, regions, labels, err := validateModel(object)
	if err != nil {
		return nil, err
	}
	mode := x86.Mode32
	if object.Machine == coff.MachineAMD64 {
		mode = x86.Mode64
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
		decoder, err = factory(ctx, mode)
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
		boundaries: map[uint32]struct{}{0: {}}, resolved: make(map[*coff.Relocation]*coff.Symbol),
		connectors: make(map[*instruction]*connector),
	}
	var expected uint64
	for index, decodedInstruction := range decoded {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("blockparty: %w", err)
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
	if err := p.associateRelocations(); err != nil {
		return nil, err
	}
	if err := p.validateControlFlow(); err != nil {
		return nil, err
	}
	p.buildBlocks()
	return p, nil
}

func validateModel(object *coff.Object) (*coff.Section, []*codeRegion, map[uint32]*coff.Symbol, error) {
	var text *coff.Section
	sections := make(map[*coff.Section]struct{}, len(object.Sections))
	names := make(map[string]struct{}, len(object.Sections))
	for index, section := range object.Sections {
		if section == nil {
			return nil, nil, nil, malformed("object validation", fmt.Errorf("section %d is nil", index))
		}
		if section.Name == "" {
			return nil, nil, nil, malformed("object validation", errors.New("empty section name"))
		}
		if _, exists := names[section.Name]; exists {
			return nil, nil, nil, malformed("object validation", fmt.Errorf("duplicate section %q", section.Name))
		}
		if section.Object != nil && section.Object != object {
			return nil, nil, nil, malformed("object validation", fmt.Errorf("section %q belongs to another object", section.Name))
		}
		sections[section] = struct{}{}
		names[section.Name] = struct{}{}
		if section.Name == ".text" {
			text = section
		}
	}
	if text == nil {
		return nil, nil, nil, malformed("object validation", errors.New("object has no .text section"))
	}
	if uint64(len(text.Data)) > math.MaxInt32 {
		return nil, nil, nil, malformed("object validation", errors.New(".text exceeds the upstream signed 32-bit size limit"))
	}

	byStart := make(map[uint32]*codeRegion)
	labels := make(map[uint32]*coff.Symbol)
	symbolNames := make(map[string]struct{}, len(object.Symbols))
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return nil, nil, nil, malformed("object validation", fmt.Errorf("symbol %d is nil", index))
		}
		if symbol.Name == "" {
			return nil, nil, nil, malformed("object validation", fmt.Errorf("symbol %d has an empty name", index))
		}
		if _, exists := symbolNames[symbol.Name]; exists {
			return nil, nil, nil, malformed("object validation", fmt.Errorf("duplicate symbol %q", symbol.Name))
		}
		symbolNames[symbol.Name] = struct{}{}
		if symbol.Section != nil {
			if _, ok := sections[symbol.Section]; !ok {
				return nil, nil, nil, malformed("object validation", fmt.Errorf("symbol %q belongs to a foreign section", symbol.Name))
			}
		}
		if symbol.Section == text && !symbol.IsFunction() && !symbol.IsGlobalVariable() && symbol.Type == 0 && symbol.Value > 0 {
			return nil, nil, nil, malformed("symbol validation", fmt.Errorf("candidate non-function/non-code symbol %q at %#x", symbol.Name, symbol.Value))
		}
		if symbol.Section != text || !symbol.IsFunction() && !symbol.IsGlobalVariable() {
			continue
		}
		if uint64(symbol.Value) >= uint64(len(text.Data)) {
			return nil, nil, nil, malformed("symbol validation", fmt.Errorf("symbol %q at %#x is outside .text", symbol.Name, symbol.Value))
		}
		if existing := byStart[symbol.Value]; existing != nil {
			return nil, nil, nil, malformed("symbol validation", fmt.Errorf("code symbols %q and %q share .text offset %#x", existing.name, symbol.Name, symbol.Value))
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
			return nil, nil, nil, malformed("symbol validation", errors.New("non-empty .text has no function or global-data symbols"))
		}
		if regions[0].start != 0 {
			return nil, nil, nil, malformed("symbol validation", fmt.Errorf("first code symbol %q starts at %#x, want zero", regions[0].name, regions[0].start))
		}
	}
	for index, region := range regions {
		region.end = uint32(len(text.Data))
		if index+1 < len(regions) {
			region.end = regions[index+1].start
		}
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

func (p *plan) associateRelocations() error {
	symbols := make(map[*coff.Symbol]struct{}, len(p.object.Symbols))
	for _, symbol := range p.object.Symbols {
		symbols[symbol] = struct{}{}
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
				symbol = p.object.GetSymbol(relocation.SymbolName)
			}
			if symbol == nil {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %d references missing symbol %q", section.Name, index, relocation.SymbolName))
			}
			if _, present := symbols[symbol]; !present {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %d references symbol %q outside the object", section.Name, index, symbol.Name))
			}
			if relocation.SymbolName != "" && relocation.SymbolName != symbol.Name {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %d names %q but points to %q", section.Name, index, relocation.SymbolName, symbol.Name))
			}
			if symbol.Section != nil && !objectContainsSection(p.object, symbol.Section) {
				return malformed("relocation validation", fmt.Errorf("relocation references symbol %q in a foreign section", symbol.Name))
			}
			width, err := relocationWidth(p.object.Machine, relocation.Type)
			if err != nil {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %d: %w", section.Name, index, err))
			}
			if uint64(relocation.VirtualAddress)+uint64(width) > uint64(len(section.Data)) {
				return malformed("relocation validation", fmt.Errorf("section %q relocation %#x is out of bounds", section.Name, relocation.VirtualAddress))
			}
			p.resolved[relocation] = symbol
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

// unsupportedRelativeEncoding recognizes position-dependent control-flow
// encodings that decodeRelative deliberately cannot rebuild without Iced's
// branch detail. In particular, legacy-prefixed branches and XBEGIN cannot be
// copied byte-for-byte after a block move.
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

func isDirectControlFlow(entry *instruction) bool {
	if entry == nil {
		return false
	}
	mnemonic := entry.mnemonic
	if mnemonic != "call" && mnemonic != "jmp" && !strings.HasPrefix(mnemonic, "j") && !strings.HasPrefix(mnemonic, "loop") {
		return false
	}
	operands := strings.TrimSpace(entry.operands)
	if operands == "" || strings.ContainsAny(operands, "[]") || isRegisterOperand(operands) {
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

func isRegisterOperand(operand string) bool {
	operand = strings.TrimSpace(strings.ToLower(operand))
	registers := []string{"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"}
	for _, register := range registers {
		if operand == register {
			return true
		}
	}
	return false
}

func (p *plan) validateControlFlow() error {
	for _, entry := range p.instructions {
		if entry.region == nil || !entry.region.isFunction {
			continue
		}
		if reason, relative := unsupportedRelativeEncoding(entry.raw); relative && !entry.hasFlow {
			return unsupported(entry, reason)
		}
		if isDirectControlFlow(entry) && !entry.hasFlow {
			return unsupported(entry, "direct control-flow encoding is not one of Iced's portable rel8/rel32 forms")
		}
		if entry.hasFlow {
			validMetadata := entry.reference.kind == relativeCall && entry.mnemonic == "call" ||
				entry.reference.kind == relativeJump && entry.mnemonic == "jmp" ||
				entry.reference.kind == relativeConditional && strings.HasPrefix(entry.mnemonic, "j") && entry.mnemonic != "jmp" ||
				entry.reference.kind == relativeLoop && (strings.HasPrefix(entry.mnemonic, "loop") || strings.Contains(entry.mnemonic, "cxz"))
			if !validMetadata {
				return unsupported(entry, "raw relative-control-flow opcode disagrees with decoder metadata")
			}
		}
		if !entry.hasFlow || entry.flowReloc {
			continue
		}
		target, err := relativeTarget(entry)
		if err != nil {
			return unsupported(entry, err.Error())
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

func unsupported(entry *instruction, reason string) *UnsupportedError {
	function := ""
	if entry != nil && entry.region != nil {
		function = entry.region.name
	}
	result := &UnsupportedError{Function: function, Reason: reason}
	if entry != nil {
		result.Offset = entry.oldStart
		result.Bytes = append([]byte(nil), entry.raw...)
	}
	return result
}

func isFunctionExit(machine coff.Machine, entry *instruction) bool {
	if entry.mnemonic == "ret" {
		return true
	}
	return machine == coff.MachineAMD64 && entry.mnemonic == "jmp" && strings.TrimSpace(entry.operands) == "rcx"
}

func (p *plan) buildBlocks() {
	targets := make(map[uint32]struct{})
	for _, entry := range p.instructions {
		if !entry.hasFlow || entry.flowReloc || entry.reference.kind == relativeCall {
			continue
		}
		target, err := relativeTarget(entry)
		if err == nil && target >= 0 && target < int64(len(p.text.Data)) {
			targets[uint32(target)] = struct{}{}
		}
	}
	for _, region := range p.regions {
		if !region.isFunction {
			continue
		}
		var current *basicBlock
		forceLeader := false
		for _, entry := range region.instructions {
			_, targeted := targets[entry.oldStart]
			if current == nil || forceLeader || targeted {
				if current != nil {
					current.hasEdge = true
					current.edgeTarget = entry.oldStart
				}
				current = &basicBlock{leader: entry.oldStart}
				region.blocks = append(region.blocks, current)
			}
			current.instructions = append(current.instructions, entry)
			forceLeader = entry.hasFlow && entry.reference.kind != relativeCall || isFunctionExit(p.object.Machine, entry)
		}
	}
}

func (p *plan) selectOrder(ctx context.Context, random boundedRandom) error {
	for _, region := range p.regions {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("blockparty: %w", err)
		}
		if !region.isFunction {
			p.order = append(p.order, region.instructions...)
			continue
		}
		p.report.Blocks += len(region.blocks)
		selected := append([]*basicBlock(nil), region.blocks...)
		if len(region.blocks) > 2 {
			p.report.EligibleFunctions++
			rest := selected[1:]
			draws, err := shuffleBlocks(rest, random)
			p.report.RandomDraws += draws
			if err != nil {
				return &stageError{stage: fmt.Sprintf("shuffle function %q", region.name), err: err}
			}
			p.report.ShuffledFunctions++
			functionReport := FunctionReport{Name: region.name}
			for _, block := range region.blocks {
				functionReport.OriginalOrder = append(functionReport.OriginalOrder, block.leader)
			}
			for _, block := range selected {
				functionReport.SelectedOrder = append(functionReport.SelectedOrder, block.leader)
			}
			p.report.Functions = append(p.report.Functions, functionReport)
		}
		region.selected = selected
		var functionOrder []*instruction
		for _, block := range selected {
			functionOrder = append(functionOrder, block.instructions...)
		}
		for index, entry := range functionOrder {
			if !entry.hasFlow || entry.flowReloc || entry.reference.kind != relativeJump || p.labelsAtTarget(entry) {
				continue
			}
			target, _ := relativeTarget(entry)
			if index+1 < len(functionOrder) && target == int64(functionOrder[index+1].oldStart) {
				entry.removed = true
				p.report.RemovedJumps++
			}
		}
		for index, block := range selected {
			if !block.hasEdge || len(block.instructions) == 0 {
				continue
			}
			last := block.instructions[len(block.instructions)-1]
			if last.mnemonic == "jmp" {
				continue
			}
			actual := uint32(math.MaxUint32)
			if index+1 < len(selected) {
				actual = selected[index+1].leader
			}
			if actual != block.edgeTarget {
				p.connectors[last] = &connector{after: last, target: block.edgeTarget, function: region.name}
				p.report.InsertedJumps++
			}
		}
		p.order = append(p.order, functionOrder...)
	}
	return nil
}

func (p *plan) labelsAtTarget(entry *instruction) bool {
	target, err := relativeTarget(entry)
	return err == nil && target >= 0 && target <= math.MaxUint32 && p.labels[uint32(target)] != nil
}
