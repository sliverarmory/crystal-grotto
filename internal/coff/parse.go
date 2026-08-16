// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package coff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	fileHeaderSize       = 20
	sectionHeaderSize    = 40
	symbolRecordSize     = 18
	relocationRecordSize = 10

	// Keep malformed BSS headers from causing unbounded allocations. This is
	// intentionally much larger than ordinary Crystal Palace modules.
	maxMaterializedSectionSize = 512 << 20
)

type reader struct {
	data []byte
	pos  int
}

func (r *reader) at(offset, size int, context string) ([]byte, error) {
	if offset < 0 || size < 0 || offset > len(r.data) || size > len(r.data)-offset {
		return nil, &ParseError{Offset: maxInt(offset, 0), Context: context, Err: errors.New("truncated or out-of-range data")}
	}
	return r.data[offset : offset+size], nil
}

func (r *reader) take(size int, context string) ([]byte, error) {
	value, err := r.at(r.pos, size, context)
	if err != nil {
		return nil, err
	}
	r.pos += size
	return value, nil
}

func (r *reader) u16(context string) (uint16, error) {
	value, err := r.take(2, context)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(value), nil
}

func (r *reader) u32(context string) (uint32, error) {
	value, err := r.take(4, context)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(value), nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func checkedSpan(offset uint32, count uint32, stride int, limit int, context string) (int, int, error) {
	start := uint64(offset)
	size := uint64(count) * uint64(stride)
	end := start + size
	if end < start || start > uint64(limit) || end > uint64(limit) {
		return 0, 0, &ParseError{Offset: int(minU64(start, uint64(limit))), Context: context, Err: errors.New("table extends beyond file")}
	}
	return int(start), int(end), nil
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

type rawSection struct {
	name                 [8]byte
	virtualSize          uint32
	virtualAddress       uint32
	sizeOfRawData        uint32
	pointerToRawData     uint32
	pointerToRelocations uint32
	pointerToLineNumbers uint32
	numberOfRelocations  uint16
	numberOfLineNumbers  uint16
	characteristics      uint32
}

type rawSymbol struct {
	name         [8]byte
	value        uint32
	section      int16
	typeValue    uint16
	storageClass uint8
	auxCount     uint8
	aux          [][]byte
	index        uint32
}

// Parse parses a Microsoft COFF object and resolves section, symbol, and
// relocation references. Returned slices do not alias the input.
func Parse(data []byte) (*Object, error) {
	r := &reader{data: data}
	if len(data) < fileHeaderSize {
		return nil, &ParseError{Context: "file header", Err: errors.New("truncated header")}
	}

	machineValue, err := r.u16("file header machine")
	if err != nil {
		return nil, err
	}
	machine := Machine(machineValue)
	object, err := NewObject(machine)
	if err != nil {
		return nil, &ParseError{Context: "file header machine", Err: err}
	}

	numberOfSections, err := r.u16("file header section count")
	if err != nil {
		return nil, err
	}
	object.TimeDateStamp, err = r.u32("file header timestamp")
	if err != nil {
		return nil, err
	}
	pointerToSymbolTable, err := r.u32("file header symbol table pointer")
	if err != nil {
		return nil, err
	}
	numberOfSymbols, err := r.u32("file header symbol count")
	if err != nil {
		return nil, err
	}
	sizeOfOptionalHeader, err := r.u16("file header optional header size")
	if err != nil {
		return nil, err
	}
	object.Characteristics, err = r.u16("file header characteristics")
	if err != nil {
		return nil, err
	}

	optional, err := r.take(int(sizeOfOptionalHeader), "optional header")
	if err != nil {
		return nil, err
	}
	object.OptionalHeader = append([]byte(nil), optional...)

	if uint64(numberOfSections)*sectionHeaderSize > uint64(len(data)-r.pos) {
		return nil, &ParseError{Offset: r.pos, Context: "section table", Err: errors.New("section headers extend beyond file")}
	}
	rawSections := make([]rawSection, int(numberOfSections))
	for index := range rawSections {
		header, err := r.take(sectionHeaderSize, fmt.Sprintf("section header %d", index))
		if err != nil {
			return nil, err
		}
		copy(rawSections[index].name[:], header[:8])
		rawSections[index].virtualSize = binary.LittleEndian.Uint32(header[8:12])
		rawSections[index].virtualAddress = binary.LittleEndian.Uint32(header[12:16])
		rawSections[index].sizeOfRawData = binary.LittleEndian.Uint32(header[16:20])
		rawSections[index].pointerToRawData = binary.LittleEndian.Uint32(header[20:24])
		rawSections[index].pointerToRelocations = binary.LittleEndian.Uint32(header[24:28])
		rawSections[index].pointerToLineNumbers = binary.LittleEndian.Uint32(header[28:32])
		rawSections[index].numberOfRelocations = binary.LittleEndian.Uint16(header[32:34])
		rawSections[index].numberOfLineNumbers = binary.LittleEndian.Uint16(header[34:36])
		rawSections[index].characteristics = binary.LittleEndian.Uint32(header[36:40])
	}

	var rawSymbols []*rawSymbol
	var stringTable []byte
	if numberOfSymbols > 0 {
		start, end, err := checkedSpan(pointerToSymbolTable, numberOfSymbols, symbolRecordSize, len(data), "symbol table")
		if err != nil {
			return nil, err
		}
		rawSymbols = make([]*rawSymbol, int(numberOfSymbols))
		for index := uint32(0); index < numberOfSymbols; {
			record := data[start+int(index)*symbolRecordSize : start+int(index+1)*symbolRecordSize]
			symbol := &rawSymbol{
				value:        binary.LittleEndian.Uint32(record[8:12]),
				section:      int16(binary.LittleEndian.Uint16(record[12:14])),
				typeValue:    binary.LittleEndian.Uint16(record[14:16]),
				storageClass: record[16],
				auxCount:     record[17],
				index:        index,
			}
			copy(symbol.name[:], record[:8])
			if uint64(index)+1+uint64(symbol.auxCount) > uint64(numberOfSymbols) {
				return nil, &ParseError{Offset: start + int(index)*symbolRecordSize, Context: fmt.Sprintf("symbol %d auxiliary records", index), Err: errors.New("auxiliary record count exceeds symbol table")}
			}
			rawSymbols[index] = symbol
			for auxIndex := uint32(0); auxIndex < uint32(symbol.auxCount); auxIndex++ {
				offset := start + int(index+1+auxIndex)*symbolRecordSize
				symbol.aux = append(symbol.aux, append([]byte(nil), data[offset:offset+symbolRecordSize]...))
			}
			index += 1 + uint32(symbol.auxCount)
		}
		stringTable, err = parseStringTable(data, end)
		if err != nil {
			return nil, err
		}
	} else if pointerToSymbolTable != 0 {
		var err error
		stringTable, err = parseStringTable(data, int(pointerToSymbolTable))
		if err != nil {
			return nil, err
		}
	}

	for index, raw := range rawSections {
		originalName, err := resolveSectionName(raw.name[:], stringTable)
		if err != nil {
			return nil, &ParseError{Offset: fileHeaderSize + int(sizeOfOptionalHeader) + index*sectionHeaderSize, Context: fmt.Sprintf("section %d name", index), Err: err}
		}
		name := originalName
		if HasFlag(raw.characteristics, SectionLinkCOMDAT) || originalName == ".xdata" {
			name = fmt.Sprintf("%s-%016X", originalName, raw.pointerToRawData)
		}
		if object.GetSection(name) != nil {
			return nil, &ParseError{Offset: fileHeaderSize + int(sizeOfOptionalHeader) + index*sectionHeaderSize, Context: fmt.Sprintf("section %d", index), Err: fmt.Errorf("duplicate normalized section name %q", name)}
		}
		if raw.sizeOfRawData > maxMaterializedSectionSize {
			return nil, &ParseError{Offset: int(raw.pointerToRawData), Context: fmt.Sprintf("section %q contents", name), Err: fmt.Errorf("section size %d exceeds safety limit", raw.sizeOfRawData)}
		}
		var contents []byte
		if HasFlag(raw.characteristics, SectionUninitializedData) {
			contents = make([]byte, int(raw.sizeOfRawData))
		} else if raw.sizeOfRawData != 0 {
			bytes, err := (&reader{data: data}).at(int(raw.pointerToRawData), int(raw.sizeOfRawData), fmt.Sprintf("section %q contents", name))
			if err != nil {
				return nil, err
			}
			contents = append([]byte(nil), bytes...)
		}
		section := &Section{
			Object:               object,
			Name:                 name,
			OriginalName:         originalName,
			VirtualSize:          raw.virtualSize,
			VirtualAddress:       raw.virtualAddress,
			SizeOfRawData:        raw.sizeOfRawData,
			PointerToRawData:     raw.pointerToRawData,
			PointerToRelocations: raw.pointerToRelocations,
			PointerToLineNumbers: raw.pointerToLineNumbers,
			NumberOfLineNumbers:  raw.numberOfLineNumbers,
			Characteristics:      raw.characteristics,
			Data:                 contents,
			Alignment:            1,
		}
		object.Sections = append(object.Sections, section)
		object.sectionsByName[name] = section
	}

	object.rawSymbols = make([]*Symbol, len(rawSymbols))
	for index, raw := range rawSymbols {
		if raw == nil {
			continue
		}
		name, err := resolveSymbolName(raw.name[:], stringTable)
		if err != nil {
			return nil, &ParseError{Offset: int(pointerToSymbolTable) + index*symbolRecordSize, Context: fmt.Sprintf("symbol %d name", index), Err: err}
		}
		var section *Section
		if raw.section >= 1 && int(raw.section) <= len(object.Sections) {
			section = object.Sections[int(raw.section)-1]
		}
		if section != nil && raw.storageClass == SymbolClassStatic && raw.value == 0 && strings.HasPrefix(name, ".") {
			name = section.Name
		} else if section != nil && raw.storageClass == SymbolClassLabel {
			name = fmt.Sprintf("%s-%016X", name, raw.value)
		}
		symbol := &Symbol{
			Name:             name,
			Value:            raw.value,
			SectionNumber:    raw.section,
			Type:             raw.typeValue,
			StorageClass:     raw.storageClass,
			AuxiliaryRecords: raw.aux,
			RawIndex:         raw.index,
			Section:          section,
		}
		object.rawSymbols[index] = symbol
		if symbol.IsLabel() {
			continue
		}
		if object.symbolsByName[name] != nil {
			return nil, &ParseError{Offset: int(pointerToSymbolTable) + index*symbolRecordSize, Context: fmt.Sprintf("symbol %d", index), Err: fmt.Errorf("duplicate symbol %q", name)}
		}
		object.Symbols = append(object.Symbols, symbol)
		object.symbolsByName[name] = symbol
	}

	for index, raw := range rawSections {
		section := object.Sections[index]
		if raw.numberOfRelocations == 0 {
			continue
		}
		start, _, err := checkedSpan(raw.pointerToRelocations, uint32(raw.numberOfRelocations), relocationRecordSize, len(data), fmt.Sprintf("section %q relocation table", section.Name))
		if err != nil {
			return nil, err
		}
		section.Relocations = make([]*Relocation, 0, raw.numberOfRelocations)
		for relocationIndex := 0; relocationIndex < int(raw.numberOfRelocations); relocationIndex++ {
			recordOffset := start + relocationIndex*relocationRecordSize
			record := data[recordOffset : recordOffset+relocationRecordSize]
			symbolIndex := binary.LittleEndian.Uint32(record[4:8])
			if uint64(symbolIndex) >= uint64(len(object.rawSymbols)) || object.rawSymbols[symbolIndex] == nil {
				return nil, &ParseError{Offset: recordOffset, Context: fmt.Sprintf("section %q relocation %d", section.Name, relocationIndex), Err: fmt.Errorf("invalid symbol table index %d", symbolIndex)}
			}
			symbol := object.rawSymbols[symbolIndex]
			section.Relocations = append(section.Relocations, &Relocation{
				Section:          section,
				VirtualAddress:   binary.LittleEndian.Uint32(record[:4]),
				SymbolTableIndex: symbolIndex,
				SymbolName:       symbol.Name,
				Type:             binary.LittleEndian.Uint16(record[8:10]),
				Symbol:           symbol,
			})
		}
	}

	return object, nil
}

// ParseMachine returns the architecture from a complete or partial COFF
// header without parsing the remaining tables.
func ParseMachine(data []byte) (Machine, error) {
	if len(data) < 2 {
		return 0, &ParseError{Context: "file header machine", Err: errors.New("truncated header")}
	}
	machine := Machine(binary.LittleEndian.Uint16(data[:2]))
	if !machine.Valid() {
		return 0, &ParseError{Context: "file header machine", Err: fmt.Errorf("unrecognized machine %#x", uint16(machine))}
	}
	return machine, nil
}

func parseStringTable(data []byte, offset int) ([]byte, error) {
	if offset < 0 || offset > len(data)-4 {
		return nil, &ParseError{Offset: maxInt(offset, 0), Context: "string table", Err: errors.New("missing length field")}
	}
	size := binary.LittleEndian.Uint32(data[offset : offset+4])
	if size < 4 {
		return nil, &ParseError{Offset: offset, Context: "string table", Err: fmt.Errorf("invalid size %d", size)}
	}
	if uint64(offset)+uint64(size) > uint64(len(data)) {
		return nil, &ParseError{Offset: offset, Context: "string table", Err: errors.New("table extends beyond file")}
	}
	return append([]byte(nil), data[offset:offset+int(size)]...), nil
}

func resolveSectionName(raw []byte, stringTable []byte) (string, error) {
	name := cString(raw)
	if !strings.HasPrefix(name, "/") {
		return name, nil
	}
	offset, err := strconv.ParseUint(name[1:], 10, 32)
	if err != nil {
		// Crystal Palace leaves malformed slash names untouched.
		return name, nil
	}
	return lookupString(stringTable, uint32(offset))
}

func resolveSymbolName(raw []byte, stringTable []byte) (string, error) {
	if len(raw) != 8 {
		return "", errors.New("symbol name field is not eight bytes")
	}
	first := binary.LittleEndian.Uint32(raw[:4])
	offset := binary.LittleEndian.Uint32(raw[4:8])
	if first == 0 && offset == 0 {
		return "", nil
	}
	if first == 0 {
		return lookupString(stringTable, offset)
	}
	return cString(raw), nil
}

func lookupString(table []byte, offset uint32) (string, error) {
	if len(table) < 4 {
		return "", errors.New("name references a missing string table")
	}
	if offset < 4 || uint64(offset) >= uint64(len(table)) {
		return "", fmt.Errorf("string-table offset %d is out of range", offset)
	}
	end := int(offset)
	for end < len(table) && table[end] != 0 {
		end++
	}
	if end == len(table) {
		return "", fmt.Errorf("string at offset %d is not NUL-terminated", offset)
	}
	return string(table[offset:uint32(end)]), nil
}

func cString(data []byte) string {
	for index, value := range data {
		if value == 0 {
			return string(data[:index])
		}
	}
	return string(data)
}
