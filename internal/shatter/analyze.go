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
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
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

type instructionRelocation struct {
	relocation *coff.Relocation
	offset     uint32
	width      uint32
}

type instruction struct {
	oldStart    uint32
	oldEnd      uint32
	raw         []byte
	mnemonic    string
	operands    string
	region      *region
	relocations []instructionRelocation
	relative    relativeReference
	hasRelative bool
	target      int64
	ripRelative bool
	ripDisp     int
	ripTarget   uint32
}

type block struct {
	region     *region
	start      uint32
	entries    []*instruction
	edgeTarget *uint32
}

type region struct {
	name         string
	start        uint32
	end          uint32
	isFunction   bool
	instructions []*instruction
	blocks       []*block
	physical     []*block
}

type fragment struct {
	entry     *instruction
	connector bool
	target    uint32
	output    []byte
	expanded  bool
	removed   bool
	region    *region
}

type plan struct {
	object       *coff.Object
	text         *coff.Section
	decoder      *x86.Capstone
	instructions []*instruction
	regions      []*region
	functions    []*region
	labels       map[uint32]*coff.Symbol
	boundaries   map[uint32]struct{}
	fragments    []*fragment
	byEntry      map[*instruction]*fragment
	report       Report
}

func newPlan(ctx context.Context, object *coff.Object) (*plan, error) {
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return nil, fmt.Errorf("shatter: unsupported machine %s", object.Machine)
	}
	text, regions, labels, err := validateModel(object)
	if err != nil {
		return nil, err
	}
	for _, section := range object.Sections {
		if strings.HasPrefix(section.Name, ".pdata") || strings.HasPrefix(section.Name, ".xdata") {
			return nil, &UnsupportedMetadataError{
				Section: section.Name,
				Reason:  "+shatter moves logical blocks across physical function boundaries and is incompatible with unwind metadata",
			}
		}
	}

	mode := x86.Mode32
	if object.Machine == coff.MachineAMD64 {
		mode = x86.Mode64
	}
	decoder, err := x86.NewCapstone(ctx, mode)
	if err != nil {
		return nil, fmt.Errorf("shatter: open disassembler: %w", err)
	}
	decoded, err := decoder.Disassemble(ctx, text.Data, 0)
	if err != nil {
		_ = decoder.Close(context.Background())
		return nil, fmt.Errorf("shatter: disassemble .text: %w", err)
	}
	p := &plan{
		object:     object,
		text:       text,
		decoder:    decoder,
		regions:    regions,
		labels:     labels,
		boundaries: map[uint32]struct{}{0: {}},
		byEntry:    make(map[*instruction]*fragment),
	}
	for _, decodedInstruction := range decoded {
		if decodedInstruction.Address > math.MaxUint32 || uint64(len(decodedInstruction.Bytes)) > math.MaxUint32-decodedInstruction.Address {
			_ = decoder.Close(context.Background())
			return nil, errors.New("shatter: instruction address overflows .text")
		}
		entry := &instruction{
			oldStart: uint32(decodedInstruction.Address),
			raw:      append([]byte(nil), decodedInstruction.Bytes...),
			mnemonic: strings.ToLower(strings.TrimSpace(decodedInstruction.Mnemonic)),
			operands: normalizeOperands(decodedInstruction.Operands),
		}
		entry.oldEnd = entry.oldStart + uint32(len(entry.raw))
		p.instructions = append(p.instructions, entry)
		p.boundaries[entry.oldEnd] = struct{}{}
	}
	for _, current := range regions {
		if _, ok := p.boundaries[current.start]; !ok {
			_ = decoder.Close(context.Background())
			return nil, fmt.Errorf("shatter: code symbol %q at %#x is not on an instruction boundary", current.name, current.start)
		}
		if _, ok := p.boundaries[current.end]; !ok {
			_ = decoder.Close(context.Background())
			return nil, fmt.Errorf("shatter: code region %q ends at non-instruction boundary %#x", current.name, current.end)
		}
		for _, entry := range p.instructions {
			if entry.oldStart >= current.start && entry.oldStart < current.end {
				entry.region = current
				current.instructions = append(current.instructions, entry)
			}
		}
		if len(current.instructions) == 0 {
			_ = decoder.Close(context.Background())
			return nil, fmt.Errorf("shatter: code region %q is empty", current.name)
		}
		if current.isFunction {
			p.functions = append(p.functions, current)
		}
	}
	if err := p.associateRelocations(); err != nil {
		_ = decoder.Close(context.Background())
		return nil, err
	}
	if err := p.analyzeControlFlow(); err != nil {
		_ = decoder.Close(context.Background())
		return nil, err
	}
	return p, nil
}

func validateModel(object *coff.Object) (*coff.Section, []*region, map[uint32]*coff.Symbol, error) {
	var text *coff.Section
	for index, section := range object.Sections {
		if section == nil {
			return nil, nil, nil, fmt.Errorf("shatter: section %d is nil", index)
		}
		if section.Object != nil && section.Object != object {
			return nil, nil, nil, fmt.Errorf("shatter: section %q belongs to another object", section.Name)
		}
		if section.Name == ".text" {
			if text != nil {
				return nil, nil, nil, errors.New("shatter: duplicate .text section")
			}
			text = section
		}
	}
	if text == nil {
		return nil, nil, nil, errors.New("shatter: object has no .text section")
	}
	if uint64(len(text.Data)) > math.MaxUint32 {
		return nil, nil, nil, errors.New("shatter: .text exceeds the COFF 32-bit size limit")
	}
	if text.PointerToLineNumbers != 0 || text.NumberOfLineNumbers != 0 {
		return nil, nil, nil, &UnsupportedMetadataError{
			Section: text.Name,
			Reason:  "COFF line-number records are not modeled and their addresses cannot be rebased",
		}
	}

	byStart := make(map[uint32]*region)
	labels := make(map[uint32]*coff.Symbol)
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return nil, nil, nil, fmt.Errorf("shatter: symbol %d is nil", index)
		}
		if symbol.Section != nil && !objectContainsSection(object, symbol.Section) {
			return nil, nil, nil, fmt.Errorf("shatter: symbol %q belongs to a foreign section", symbol.Name)
		}
		if !utf8.ValidString(symbol.Name) {
			return nil, nil, nil, fmt.Errorf("shatter: symbol name %q is not valid UTF-8 and has no provable Java String hash", symbol.Name)
		}
		for auxiliaryIndex, record := range symbol.AuxiliaryRecords {
			if len(record) != 18 {
				return nil, nil, nil, fmt.Errorf("shatter: symbol %q auxiliary record %d has length %d, want 18", symbol.Name, auxiliaryIndex, len(record))
			}
		}
		if symbol.Section != text {
			continue
		}
		// Some preceding Go-native order passes move the static section symbol
		// with its original code chunk. Upstream keeps this section-base symbol
		// at zero. Recognize it independently of IsSectionName(), whose model
		// predicate intentionally requires Value == 0, and normalize at commit.
		if isTextSectionSymbol(symbol, text) {
			continue
		}
		active := symbol.IsFunction() || symbol.IsGlobalVariable()
		if !active {
			if symbol.Type == 0 && symbol.Value > 0 {
				return nil, nil, nil, fmt.Errorf("shatter: unsupported non-function .text symbol %q at %#x", symbol.Name, symbol.Value)
			}
			continue
		}
		if symbol.Value >= uint32(len(text.Data)) && len(text.Data) != 0 {
			return nil, nil, nil, fmt.Errorf("shatter: symbol %q at %#x is outside executable .text", symbol.Name, symbol.Value)
		}
		if existing := byStart[symbol.Value]; existing != nil {
			return nil, nil, nil, fmt.Errorf("shatter: code symbols %q and %q share .text offset %#x", existing.name, symbol.Name, symbol.Value)
		}
		current := &region{name: symbol.Name, start: symbol.Value, isFunction: symbol.IsFunction()}
		byStart[symbol.Value] = current
		labels[symbol.Value] = symbol
	}
	regions := make([]*region, 0, len(byStart))
	for _, current := range byStart {
		regions = append(regions, current)
	}
	sort.Slice(regions, func(i, j int) bool {
		if regions[i].start != regions[j].start {
			return regions[i].start < regions[j].start
		}
		return regions[i].name < regions[j].name
	})
	if len(text.Data) != 0 {
		if len(regions) == 0 {
			return nil, nil, nil, errors.New("shatter: non-empty .text has no function or global-data symbols")
		}
		if regions[0].start != 0 {
			return nil, nil, nil, fmt.Errorf("shatter: bytes before first .text symbol at %#x cannot be preserved by upstream's function map", regions[0].start)
		}
	}
	for index, current := range regions {
		current.end = uint32(len(text.Data))
		if index+1 < len(regions) {
			current.end = regions[index+1].start
		}
	}
	return text, regions, labels, nil
}

func isTextSectionSymbol(symbol *coff.Symbol, text *coff.Section) bool {
	return symbol != nil && text != nil && symbol.Section == text && symbol.Name == text.Name && symbol.Type == 0 && symbol.StorageClass == coff.SymbolClassStatic
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
				return fmt.Errorf("shatter: section %q relocation %d is nil", section.Name, index)
			}
			if relocation.Section != nil && relocation.Section != section {
				return fmt.Errorf("shatter: section %q relocation %d has a foreign parent", section.Name, index)
			}
			if relocation.Symbol == nil {
				return fmt.Errorf("shatter: section %q relocation %d references missing symbol %q", section.Name, index, relocation.SymbolName)
			}
			if _, ok := symbols[relocation.Symbol]; !ok {
				return fmt.Errorf("shatter: section %q relocation %d references symbol %q outside the object", section.Name, index, relocation.Symbol.Name)
			}
			if relocation.SymbolName != "" && relocation.SymbolName != relocation.Symbol.Name {
				return fmt.Errorf("shatter: section %q relocation %d names %q but points to %q", section.Name, index, relocation.SymbolName, relocation.Symbol.Name)
			}
			if relocation.Symbol.Section != nil && !objectContainsSection(p.object, relocation.Symbol.Section) {
				return fmt.Errorf("shatter: relocation references symbol %q in a foreign section", relocation.Symbol.Name)
			}
			width, err := relocationWidth(p.object.Machine, relocation.Type)
			if err != nil {
				return fmt.Errorf("shatter: section %q relocation %d: %w", section.Name, index, err)
			}
			if uint64(relocation.VirtualAddress)+uint64(width) > uint64(len(section.Data)) {
				return fmt.Errorf("shatter: section %q relocation %#x is out of bounds", section.Name, relocation.VirtualAddress)
			}
			if section != p.text {
				continue
			}
			entry := instructionAt(p.instructions, relocation.VirtualAddress)
			if entry == nil || uint64(relocation.VirtualAddress)+uint64(width) > uint64(entry.oldEnd) {
				return fmt.Errorf("shatter: .text relocation %#x is not wholly inside one instruction", relocation.VirtualAddress)
			}
			entry.relocations = append(entry.relocations, instructionRelocation{
				relocation: relocation,
				offset:     relocation.VirtualAddress - entry.oldStart,
				width:      width,
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

func (p *plan) analyzeControlFlow() error {
	for _, entry := range p.instructions {
		if err := p.checkContext(entry); err != nil {
			return err
		}
		reference, relative := decodeRelative(entry.raw)
		entry.relative, entry.hasRelative = reference, relative
		if relative {
			target, err := relativeTarget(entry, reference)
			if err != nil {
				return p.unsupported(entry, err.Error())
			}
			entry.target = target
			if len(entry.relocations) == 0 {
				if target < 0 || target >= int64(len(p.text.Data)) {
					return p.unsupported(entry, "relative control flow targets outside .text without a relocation")
				}
				if _, ok := p.boundaries[uint32(target)]; !ok {
					return p.unsupported(entry, fmt.Sprintf("relative target %#x is not an instruction boundary", target))
				}
				if reference.kind == relativeCall && p.labels[uint32(target)] == nil {
					return p.unsupported(entry, fmt.Sprintf("near call target %#x has no COFF code symbol", target))
				}
			}
		} else if isUnprovenDirectControlFlow(entry) {
			return p.unsupported(entry, "direct control-flow form is not exposed by go-capstone v0.0.1 and is not a supported raw encoding")
		}

		if p.object.Machine == coff.MachineAMD64 && hasWord(entry.operands, "rip") {
			if len(entry.relocations) != 0 {
				continue
			}
			displacement, target, err := decodeRIPRelative(entry)
			if err != nil {
				return p.unsupported(entry, err.Error())
			}
			if target < 0 || target >= int64(len(p.text.Data)) || p.labels[uint32(target)] == nil {
				return p.unsupported(entry, fmt.Sprintf("RIP-relative target %#x has no COFF code symbol", target))
			}
			entry.ripRelative = true
			entry.ripDisp = displacement
			entry.ripTarget = uint32(target)
		}
		if !entry.region.isFunction && (entry.hasRelative || entry.ripRelative || isIndirectControlFlow(entry)) {
			return p.unsupported(entry, "control-flow-like bytes in a global-data region cannot be safely reassembled")
		}
	}
	return nil
}

func (p *plan) checkContext(entry *instruction) error {
	if entry.region == nil {
		return fmt.Errorf("shatter: instruction %#x has no code region", entry.oldStart)
	}
	return nil
}

func (p *plan) unsupported(entry *instruction, reason string) error {
	function := ""
	if entry != nil && entry.region != nil {
		function = entry.region.name
	}
	var offset uint32
	var raw []byte
	if entry != nil {
		offset = entry.oldStart
		raw = append([]byte(nil), entry.raw...)
	}
	return &UnsupportedControlFlowError{Function: function, Offset: offset, Bytes: raw, Reason: reason}
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

func relativeTarget(entry *instruction, reference relativeReference) (int64, error) {
	if reference.offset < 0 || reference.size <= 0 || reference.offset+reference.size > len(entry.raw) {
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

func isUnprovenDirectControlFlow(entry *instruction) bool {
	if entry == nil {
		return false
	}
	name := entry.mnemonic
	if name == "xbegin" || name == "ljmp" || name == "lcall" {
		return true
	}
	if name == "ret" || name == "retf" || name == "iret" || strings.HasPrefix(name, "iret") {
		return false
	}
	if name != "call" && name != "jmp" && !strings.HasPrefix(name, "j") && !strings.HasPrefix(name, "loop") {
		return false
	}
	return !isIndirectControlFlow(entry)
}

func isIndirectControlFlow(entry *instruction) bool {
	if entry == nil || (entry.mnemonic != "call" && entry.mnemonic != "jmp") {
		return false
	}
	position := skipPrefixes(entry.raw)
	if position+2 > len(entry.raw) || entry.raw[position] != 0xff {
		return false
	}
	modrm := entry.raw[position+1]
	operation := (modrm >> 3) & 7
	return operation == 2 || operation == 4
}

func normalizeOperands(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

func hasWord(value, word string) bool {
	for _, field := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
	}) {
		if field == word {
			return true
		}
	}
	return false
}

func skipPrefixes(raw []byte) int {
	position := 0
	for position < len(raw) && isLegacyPrefix(raw[position]) {
		position++
	}
	for position < len(raw) && raw[position] >= 0x40 && raw[position] <= 0x4f {
		position++
	}
	return position
}

func isLegacyPrefix(value byte) bool {
	switch value {
	case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3:
		return true
	default:
		return false
	}
}

func javaHashOrder(functions []*region) ([]*region, error) {
	ordered := append([]*region(nil), functions...)
	capacity := uint32(16)
	for len(ordered) > int(capacity-capacity/4) {
		capacity <<= 1
		if capacity == 0 {
			return nil, errors.New("shatter: too many functions for Java HashMap ordering")
		}
	}
	type hashInfo struct {
		region *region
		bucket uint32
		order  int
	}
	infos := make([]hashInfo, len(ordered))
	buckets := make(map[uint32]int)
	for index, current := range ordered {
		hash := javaStringHash(current.name)
		spread := hash ^ (hash >> 16)
		bucket := spread & (capacity - 1)
		buckets[bucket]++
		if capacity >= 64 && buckets[bucket] >= 8 {
			return nil, fmt.Errorf("shatter: Java HashMap tree-bin ordering for function %q is unsupported", current.name)
		}
		infos[index] = hashInfo{region: current, bucket: bucket, order: index}
	}
	sort.SliceStable(infos, func(i, j int) bool {
		if infos[i].bucket != infos[j].bucket {
			return infos[i].bucket < infos[j].bucket
		}
		return infos[i].order < infos[j].order
	})
	for index := range infos {
		ordered[index] = infos[index].region
	}
	return ordered, nil
}

func javaStringHash(value string) uint32 {
	var hash uint32
	// Java String.hashCode operates on UTF-16 code units. COFF names are
	// overwhelmingly ASCII, but handle supplementary runes exactly as UTF-16.
	for _, r := range value {
		if r <= 0xffff {
			hash = hash*31 + uint32(r)
			continue
		}
		r -= 0x10000
		high := uint32(0xd800 + (r >> 10))
		low := uint32(0xdc00 + (r & 0x3ff))
		hash = hash*31 + high
		hash = hash*31 + low
	}
	return hash
}
