// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.
// See LICENSE.upstream.

package coffwrite

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

const (
	fileHeaderSize       = 20
	sectionHeaderSize    = 40
	symbolRecordSize     = 18
	relocationRecordSize = 10

	// Match the parser's per-section safety boundary and prevent a malformed
	// alignment value from asking Marshal to allocate several gigabytes.
	maximumOutputSize = 512 << 20
)

// Marshal returns a deterministic Microsoft COFF object. It does not mutate
// object fields such as RawIndex, SymbolTableIndex, or file pointers.
func Marshal(object *coff.Object) ([]byte, error) {
	plan, err := makePlan(object)
	if err != nil {
		return nil, err
	}
	return plan.marshal(), nil
}

type plan struct {
	object         *coff.Object
	sections       []sectionPlan
	symbols        []symbolPlan
	symbolCount    uint32
	symbolOffset   uint32
	stringOffset   uint32
	strings        *stringTable
	totalSize      int
	sectionIndices map[*coff.Section]int16
	symbolIndices  map[*coff.Symbol]uint32
}

type sectionPlan struct {
	section          *coff.Section
	rawName          string
	rawOffset        uint32
	relocationOffset uint32
	relocations      []relocationPlan
}

type relocationPlan struct {
	relocation  *coff.Relocation
	symbolIndex uint32
}

type symbolPlan struct {
	symbol        *coff.Symbol
	encodedName   string
	sectionNumber int16
	rawIndex      uint32
}

func makePlan(object *coff.Object) (*plan, error) {
	if object == nil {
		return nil, errors.New("coffwrite: object is nil")
	}
	if !object.Machine.Valid() {
		return nil, fmt.Errorf("coffwrite: unsupported machine %#x", uint16(object.Machine))
	}
	if len(object.OptionalHeader) > math.MaxUint16 {
		return nil, fmt.Errorf("coffwrite: optional header is %d bytes; maximum is %d", len(object.OptionalHeader), math.MaxUint16)
	}
	if len(object.Sections) > math.MaxInt16 {
		return nil, fmt.Errorf("coffwrite: %d sections exceed the modeled section-number limit %d", len(object.Sections), math.MaxInt16)
	}

	p := &plan{
		object:         object,
		strings:        newStringTable(),
		sectionIndices: make(map[*coff.Section]int16, len(object.Sections)),
		symbolIndices:  make(map[*coff.Symbol]uint32, len(object.Symbols)),
	}
	sectionNames := make(map[string]struct{}, len(object.Sections))
	for index, section := range object.Sections {
		if section == nil {
			return nil, fmt.Errorf("coffwrite: section %d is nil", index)
		}
		if _, exists := p.sectionIndices[section]; exists {
			return nil, fmt.Errorf("coffwrite: section %d repeats section %q", index, section.Name)
		}
		if section.Name == "" {
			return nil, fmt.Errorf("coffwrite: section %d has an empty name", index)
		}
		if _, exists := sectionNames[section.Name]; exists {
			return nil, fmt.Errorf("coffwrite: duplicate section name %q", section.Name)
		}
		if section.Object != nil && section.Object != object {
			return nil, fmt.Errorf("coffwrite: section %q belongs to a different object", section.Name)
		}
		if section.PointerToLineNumbers != 0 || section.NumberOfLineNumbers != 0 {
			return nil, fmt.Errorf("coffwrite: section %q has line-number metadata but the model retains no line-number records", section.Name)
		}
		if uint64(len(section.Data)) > math.MaxUint32 {
			return nil, fmt.Errorf("coffwrite: section %q data exceeds 32-bit COFF size", section.Name)
		}
		alignment := section.Alignment
		if alignment == 0 {
			alignment = 1
		}
		if alignment&(alignment-1) != 0 {
			return nil, fmt.Errorf("coffwrite: section %q alignment %d is not a power of two", section.Name, alignment)
		}
		if len(section.Relocations) > math.MaxUint16 {
			return nil, fmt.Errorf("coffwrite: section %q has %d relocations; overflow records are not modeled", section.Name, len(section.Relocations))
		}
		if section.IsUninitialized() && len(section.Relocations) != 0 {
			return nil, fmt.Errorf("coffwrite: uninitialized section %q has relocations", section.Name)
		}

		rawName := section.OriginalName
		if rawName == "" {
			rawName = section.Name
		}
		if err := validateName(rawName, "section", index); err != nil {
			return nil, err
		}
		if _, err := p.strings.add(rawName); err != nil {
			return nil, fmt.Errorf("coffwrite: section %q name: %w", section.Name, err)
		}
		p.sectionIndices[section] = int16(index + 1)
		sectionNames[section.Name] = struct{}{}
		p.sections = append(p.sections, sectionPlan{section: section, rawName: rawName})
	}

	symbolNames := make(map[string]*coff.Symbol, len(object.Symbols))
	var rawSymbolCount uint64
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return nil, fmt.Errorf("coffwrite: symbol %d is nil", index)
		}
		if _, exists := p.symbolIndices[symbol]; exists {
			return nil, fmt.Errorf("coffwrite: symbol %d repeats symbol %q", index, symbol.Name)
		}
		if symbol.Name == "" {
			return nil, fmt.Errorf("coffwrite: symbol %d has an empty name", index)
		}
		if strings.IndexByte(symbol.Name, 0) >= 0 {
			return nil, fmt.Errorf("coffwrite: symbol %d name contains NUL", index)
		}
		if previous := symbolNames[symbol.Name]; previous != nil {
			return nil, fmt.Errorf("coffwrite: duplicate symbol name %q", symbol.Name)
		}
		if len(symbol.AuxiliaryRecords) > math.MaxUint8 {
			return nil, fmt.Errorf("coffwrite: symbol %q has %d auxiliary records; maximum is %d", symbol.Name, len(symbol.AuxiliaryRecords), math.MaxUint8)
		}
		for auxiliaryIndex, record := range symbol.AuxiliaryRecords {
			if len(record) != symbolRecordSize {
				return nil, fmt.Errorf("coffwrite: symbol %q auxiliary record %d is %d bytes; want %d", symbol.Name, auxiliaryIndex, len(record), symbolRecordSize)
			}
		}

		sectionNumber := symbol.SectionNumber
		if symbol.Section != nil {
			var exists bool
			sectionNumber, exists = p.sectionIndices[symbol.Section]
			if !exists {
				return nil, fmt.Errorf("coffwrite: symbol %q refers to a section outside the object", symbol.Name)
			}
		} else if sectionNumber > 0 {
			return nil, fmt.Errorf("coffwrite: symbol %q has section number %d but no section pointer", symbol.Name, sectionNumber)
		}

		encodedName := symbol.Name
		if symbol.Section != nil && symbol.IsSectionName() {
			encodedName = p.sections[int(sectionNumber)-1].rawName
		}
		if strings.IndexByte(encodedName, 0) >= 0 {
			return nil, fmt.Errorf("coffwrite: encoded symbol %q name contains NUL", symbol.Name)
		}
		if _, err := p.strings.add(encodedName); err != nil {
			return nil, fmt.Errorf("coffwrite: symbol %q name: %w", symbol.Name, err)
		}
		if rawSymbolCount > math.MaxUint32 {
			return nil, errors.New("coffwrite: symbol table exceeds 32-bit record count")
		}
		rawIndex := uint32(rawSymbolCount)
		p.symbolIndices[symbol] = rawIndex
		symbolNames[symbol.Name] = symbol
		p.symbols = append(p.symbols, symbolPlan{symbol: symbol, encodedName: encodedName, sectionNumber: sectionNumber, rawIndex: rawIndex})
		rawSymbolCount += 1 + uint64(len(symbol.AuxiliaryRecords))
		if rawSymbolCount > math.MaxUint32 {
			return nil, errors.New("coffwrite: symbol table exceeds 32-bit record count")
		}
	}
	p.symbolCount = uint32(rawSymbolCount)

	for sectionIndex := range p.sections {
		sectionPlan := &p.sections[sectionIndex]
		section := sectionPlan.section
		for relocationIndex, relocation := range section.Relocations {
			if relocation == nil {
				return nil, fmt.Errorf("coffwrite: section %q relocation %d is nil", section.Name, relocationIndex)
			}
			if relocation.Section != nil && relocation.Section != section {
				return nil, fmt.Errorf("coffwrite: section %q relocation %d belongs to section %q", section.Name, relocationIndex, relocation.Section.Name)
			}
			if uint64(relocation.VirtualAddress) >= uint64(len(section.Data)) {
				return nil, fmt.Errorf("coffwrite: section %q relocation %d address %#x is outside %d bytes", section.Name, relocationIndex, relocation.VirtualAddress, len(section.Data))
			}

			target := relocation.Symbol
			if target != nil {
				if _, exists := p.symbolIndices[target]; !exists {
					return nil, fmt.Errorf("coffwrite: section %q relocation %d references symbol %q outside the object", section.Name, relocationIndex, target.Name)
				}
				if relocation.SymbolName != "" && relocation.SymbolName != target.Name {
					return nil, fmt.Errorf("coffwrite: section %q relocation %d names symbol %q but points to %q", section.Name, relocationIndex, relocation.SymbolName, target.Name)
				}
			} else {
				if relocation.SymbolName == "" {
					return nil, fmt.Errorf("coffwrite: section %q relocation %d has no symbol", section.Name, relocationIndex)
				}
				target = symbolNames[relocation.SymbolName]
				if target == nil {
					return nil, fmt.Errorf("coffwrite: section %q relocation %d references missing symbol %q", section.Name, relocationIndex, relocation.SymbolName)
				}
			}
			name := relocation.SymbolName
			if name == "" {
				name = target.Name
			}
			if _, err := p.strings.add(name); err != nil {
				return nil, fmt.Errorf("coffwrite: section %q relocation %d symbol name: %w", section.Name, relocationIndex, err)
			}
			sectionPlan.relocations = append(sectionPlan.relocations, relocationPlan{relocation: relocation, symbolIndex: p.symbolIndices[target]})
		}
	}

	if err := p.layout(); err != nil {
		return nil, err
	}
	if err := p.validateParsedNames(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *plan) layout() error {
	current := uint64(fileHeaderSize + len(p.object.OptionalHeader) + len(p.sections)*sectionHeaderSize)
	for index := range p.sections {
		entry := &p.sections[index]
		section := entry.section
		if section.IsUninitialized() {
			continue
		}
		entry.relocationOffset = uint32(current)
		current += uint64(len(entry.relocations)) * relocationRecordSize
		if len(section.Data) != 0 {
			alignment := uint64(section.Alignment)
			if alignment == 0 {
				alignment = 1
			}
			current = alignUp(current, alignment)
		}
		if current > math.MaxUint32 {
			return fmt.Errorf("coffwrite: section %q raw-data pointer exceeds 32 bits", section.Name)
		}
		entry.rawOffset = uint32(current)
		current += uint64(len(section.Data))
		if current > math.MaxUint32 {
			return fmt.Errorf("coffwrite: section %q makes output exceed 32-bit COFF offsets", section.Name)
		}
	}

	p.symbolOffset = uint32(current)
	current += uint64(p.symbolCount) * symbolRecordSize
	if current > math.MaxUint32 {
		return errors.New("coffwrite: symbol table makes output exceed 32-bit COFF offsets")
	}
	p.stringOffset = uint32(current)
	current += uint64(p.strings.size())
	if current > math.MaxUint32 || current > maximumOutputSize || current > uint64(maxInt()) {
		return fmt.Errorf("coffwrite: serialized object size %d exceeds safety limit %d", current, maximumOutputSize)
	}
	p.totalSize = int(current)

	for _, section := range p.sections {
		if len(section.rawName) <= 8 {
			continue
		}
		offset := p.strings.offset(section.rawName)
		reference := fmt.Sprintf("/%d", offset)
		if len(reference) > 8 {
			return fmt.Errorf("coffwrite: section %q string-table offset %d does not fit an eight-byte decimal reference", section.section.Name, offset)
		}
	}
	return nil
}

// validateParsedNames mirrors coff.Parse's section/static-symbol normalization
// so every successful Marshal result is accepted by that parser. This matters
// when distinct in-memory normalized names share one OriginalName.
func (p *plan) validateParsedNames() error {
	sectionNames := make(map[string]struct{}, len(p.sections))
	normalized := make(map[*coff.Section]string, len(p.sections))
	for _, entry := range p.sections {
		name := entry.rawName
		if entry.section.IsCOMDAT() || entry.rawName == ".xdata" {
			name = fmt.Sprintf("%s-%016X", entry.rawName, entry.rawOffset)
		}
		if _, exists := sectionNames[name]; exists {
			return fmt.Errorf("coffwrite: serialized sections normalize to duplicate name %q", name)
		}
		sectionNames[name] = struct{}{}
		normalized[entry.section] = name
	}

	symbolNames := make(map[string]struct{}, len(p.symbols))
	for _, entry := range p.symbols {
		if entry.symbol.IsLabel() {
			continue
		}
		name := entry.encodedName
		if entry.symbol.Section != nil && entry.symbol.StorageClass == coff.SymbolClassStatic && entry.symbol.Value == 0 && strings.HasPrefix(name, ".") {
			name = normalized[entry.symbol.Section]
		}
		if _, exists := symbolNames[name]; exists {
			return fmt.Errorf("coffwrite: serialized symbols normalize to duplicate name %q", name)
		}
		symbolNames[name] = struct{}{}
	}
	return nil
}

func (p *plan) marshal() []byte {
	output := make([]byte, p.totalSize)
	binary.LittleEndian.PutUint16(output[0:2], uint16(p.object.Machine))
	binary.LittleEndian.PutUint16(output[2:4], uint16(len(p.sections)))
	binary.LittleEndian.PutUint32(output[4:8], p.object.TimeDateStamp)
	binary.LittleEndian.PutUint32(output[8:12], p.symbolOffset)
	binary.LittleEndian.PutUint32(output[12:16], p.symbolCount)
	binary.LittleEndian.PutUint16(output[16:18], uint16(len(p.object.OptionalHeader)))
	binary.LittleEndian.PutUint16(output[18:20], p.object.Characteristics)
	copy(output[fileHeaderSize:], p.object.OptionalHeader)

	sectionTableOffset := fileHeaderSize + len(p.object.OptionalHeader)
	for index, entry := range p.sections {
		header := output[sectionTableOffset+index*sectionHeaderSize : sectionTableOffset+(index+1)*sectionHeaderSize]
		putSectionName(header[:8], entry.rawName, p.strings.offset(entry.rawName))
		section := entry.section
		binary.LittleEndian.PutUint32(header[8:12], section.VirtualSize)
		binary.LittleEndian.PutUint32(header[12:16], section.VirtualAddress)
		binary.LittleEndian.PutUint32(header[16:20], uint32(len(section.Data)))
		if !section.IsUninitialized() {
			binary.LittleEndian.PutUint32(header[20:24], entry.rawOffset)
			binary.LittleEndian.PutUint32(header[24:28], entry.relocationOffset)
		}
		binary.LittleEndian.PutUint16(header[32:34], uint16(len(entry.relocations)))
		binary.LittleEndian.PutUint32(header[36:40], section.Characteristics)

		for relocationIndex, relocation := range entry.relocations {
			offset := int(entry.relocationOffset) + relocationIndex*relocationRecordSize
			record := output[offset : offset+relocationRecordSize]
			binary.LittleEndian.PutUint32(record[0:4], relocation.relocation.VirtualAddress)
			binary.LittleEndian.PutUint32(record[4:8], relocation.symbolIndex)
			binary.LittleEndian.PutUint16(record[8:10], relocation.relocation.Type)
		}
		if !section.IsUninitialized() {
			copy(output[int(entry.rawOffset):], section.Data)
		}
	}

	for _, entry := range p.symbols {
		offset := int(p.symbolOffset) + int(entry.rawIndex)*symbolRecordSize
		record := output[offset : offset+symbolRecordSize]
		binary.LittleEndian.PutUint32(record[4:8], p.strings.offset(entry.encodedName))
		binary.LittleEndian.PutUint32(record[8:12], entry.symbol.Value)
		binary.LittleEndian.PutUint16(record[12:14], uint16(entry.sectionNumber))
		binary.LittleEndian.PutUint16(record[14:16], entry.symbol.Type)
		record[16] = entry.symbol.StorageClass
		record[17] = byte(len(entry.symbol.AuxiliaryRecords))
		for auxiliaryIndex, auxiliary := range entry.symbol.AuxiliaryRecords {
			auxiliaryOffset := offset + (auxiliaryIndex+1)*symbolRecordSize
			copy(output[auxiliaryOffset:auxiliaryOffset+symbolRecordSize], auxiliary)
		}
	}
	copy(output[int(p.stringOffset):], p.strings.bytes())
	return output
}

func putSectionName(destination []byte, name string, stringOffset uint32) {
	if len(name) <= len(destination) {
		copy(destination, name)
		return
	}
	copy(destination, fmt.Sprintf("/%d", stringOffset))
}

func validateName(name, kind string, index int) error {
	if name == "" {
		return fmt.Errorf("coffwrite: %s %d has an empty name", kind, index)
	}
	if strings.IndexByte(name, 0) >= 0 {
		return fmt.Errorf("coffwrite: %s %d name contains NUL", kind, index)
	}
	return nil
}

func alignUp(value, alignment uint64) uint64 {
	mask := alignment - 1
	return (value + mask) &^ mask
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

type stringTable struct {
	body    []byte
	offsets map[string]uint32
}

func newStringTable() *stringTable {
	return &stringTable{offsets: make(map[string]uint32)}
}

func (s *stringTable) add(value string) (uint32, error) {
	if offset, exists := s.offsets[value]; exists {
		return offset, nil
	}
	offset := uint64(4) + uint64(len(s.body))
	size := offset + uint64(len(value)) + 1
	if offset > math.MaxUint32 || size > math.MaxUint32 {
		return 0, errors.New("string table exceeds 32-bit COFF size")
	}
	s.offsets[value] = uint32(offset)
	s.body = append(s.body, value...)
	s.body = append(s.body, 0)
	return uint32(offset), nil
}

func (s *stringTable) offset(value string) uint32 {
	return s.offsets[value]
}

func (s *stringTable) size() int {
	return 4 + len(s.body)
}

func (s *stringTable) bytes() []byte {
	result := make([]byte, s.size())
	binary.LittleEndian.PutUint32(result[:4], uint32(len(result)))
	copy(result[4:], s.body)
	return result
}
