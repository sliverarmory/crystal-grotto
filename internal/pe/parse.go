// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

const (
	dosHeaderSize        = 64
	coffHeaderSize       = 20
	sectionHeaderSize    = 40
	importDescriptorSize = 20
	maxImportDescriptors = 1 << 16
	maxImportThunks      = 1 << 20
)

// ParseMachine performs the same lightweight MZ/PE validation used to choose
// a Crystal Palace capability target.
func ParseMachine(data []byte) (coff.Machine, error) {
	peOffset, err := locatePE(data)
	if err != nil {
		return 0, err
	}
	machine := coff.Machine(binary.LittleEndian.Uint16(data[peOffset+4 : peOffset+6]))
	if !machine.Valid() {
		return 0, &ParseError{Offset: peOffset + 4, Context: "COFF machine", Err: fmt.Errorf("unrecognized machine %#x", uint16(machine))}
	}
	return machine, nil
}

// Parse parses PE32 or PE32+ section layout, optional-header metadata, and the
// standard import directory without allocating a SizeOfImage-sized buffer.
func Parse(data []byte) (*Object, error) {
	peOffset, err := locatePE(data)
	if err != nil {
		return nil, err
	}
	coffOffset := peOffset + 4
	if coffOffset+coffHeaderSize > len(data) {
		return nil, &ParseError{Offset: coffOffset, Context: "COFF header", Err: errors.New("truncated header")}
	}
	header := data[coffOffset : coffOffset+coffHeaderSize]
	machine := coff.Machine(binary.LittleEndian.Uint16(header[:2]))
	if !machine.Valid() {
		return nil, &ParseError{Offset: coffOffset, Context: "COFF machine", Err: fmt.Errorf("unrecognized machine %#x", uint16(machine))}
	}
	numberOfSections := binary.LittleEndian.Uint16(header[2:4])
	sizeOfOptionalHeader := binary.LittleEndian.Uint16(header[16:18])
	object := &Object{
		Machine:         machine,
		TimeDateStamp:   binary.LittleEndian.Uint32(header[4:8]),
		Characteristics: binary.LittleEndian.Uint16(header[18:20]),
		file:            append([]byte(nil), data...),
	}

	optionalOffset := coffOffset + coffHeaderSize
	optionalEnd := optionalOffset + int(sizeOfOptionalHeader)
	if optionalEnd < optionalOffset || optionalEnd > len(data) {
		return nil, &ParseError{Offset: optionalOffset, Context: "optional header", Err: errors.New("header extends beyond file")}
	}
	optional, err := parseOptionalHeader(data[optionalOffset:optionalEnd], optionalOffset)
	if err != nil {
		return nil, err
	}
	object.OptionalHeader = optional

	sectionTableOffset := optionalEnd
	sectionBytes := uint64(numberOfSections) * sectionHeaderSize
	if uint64(sectionTableOffset)+sectionBytes > uint64(len(data)) {
		return nil, &ParseError{Offset: sectionTableOffset, Context: "section table", Err: errors.New("section headers extend beyond file")}
	}
	object.Sections = make([]*Section, 0, numberOfSections)
	for index := 0; index < int(numberOfSections); index++ {
		offset := sectionTableOffset + index*sectionHeaderSize
		raw := data[offset : offset+sectionHeaderSize]
		section := &Section{
			Name:                 cString(raw[:8]),
			VirtualSize:          binary.LittleEndian.Uint32(raw[8:12]),
			VirtualAddress:       binary.LittleEndian.Uint32(raw[12:16]),
			SizeOfRawData:        binary.LittleEndian.Uint32(raw[16:20]),
			PointerToRawData:     binary.LittleEndian.Uint32(raw[20:24]),
			PointerToRelocations: binary.LittleEndian.Uint32(raw[24:28]),
			PointerToLineNumbers: binary.LittleEndian.Uint32(raw[28:32]),
			NumberOfRelocations:  binary.LittleEndian.Uint16(raw[32:34]),
			NumberOfLineNumbers:  binary.LittleEndian.Uint16(raw[34:36]),
			Characteristics:      binary.LittleEndian.Uint32(raw[36:40]),
		}
		if section.SizeOfRawData != 0 {
			start := uint64(section.PointerToRawData)
			end := start + uint64(section.SizeOfRawData)
			if end < start || end > uint64(len(data)) {
				return nil, &ParseError{Offset: int(minU64(start, uint64(len(data)))), Context: fmt.Sprintf("section %q contents", section.Name), Err: errors.New("raw data extends beyond file")}
			}
			section.Data = append([]byte(nil), data[start:end]...)
		}
		object.Sections = append(object.Sections, section)
	}

	if err := object.parseImports(); err != nil {
		return nil, err
	}
	return object, nil
}

func locatePE(data []byte) (int, error) {
	if len(data) < dosHeaderSize {
		return 0, &ParseError{Context: "DOS header", Err: errors.New("truncated header")}
	}
	if binary.LittleEndian.Uint16(data[:2]) != 0x5a4d {
		return 0, &ParseError{Context: "DOS header", Err: errors.New("file header is not MZ")}
	}
	offset := binary.LittleEndian.Uint32(data[0x3c:0x40])
	if uint64(offset)+4+coffHeaderSize > uint64(len(data)) {
		return 0, &ParseError{Offset: int(minU64(uint64(offset), uint64(len(data)))), Context: "PE header", Err: errors.New("e_lfanew points outside file")}
	}
	if binary.LittleEndian.Uint32(data[offset:offset+4]) != 0x00004550 {
		return 0, &ParseError{Offset: int(offset), Context: "PE signature", Err: errors.New("signature is not PE\\x00\\x00")}
	}
	return int(offset), nil
}

func parseOptionalHeader(data []byte, fileOffset int) (OptionalHeader, error) {
	if len(data) < 2 {
		return OptionalHeader{}, &ParseError{Offset: fileOffset, Context: "optional header", Err: errors.New("missing magic")}
	}
	result := OptionalHeader{Magic: binary.LittleEndian.Uint16(data[:2])}
	var directoryOffset int
	switch result.Magic {
	case OptionalMagicPE32:
		if len(data) < 96 {
			return OptionalHeader{}, &ParseError{Offset: fileOffset, Context: "PE32 optional header", Err: errors.New("truncated fixed fields")}
		}
		result.AddressOfEntryPoint = binary.LittleEndian.Uint32(data[16:20])
		result.ImageBase = uint64(binary.LittleEndian.Uint32(data[28:32]))
		result.SectionAlignment = binary.LittleEndian.Uint32(data[32:36])
		result.FileAlignment = binary.LittleEndian.Uint32(data[36:40])
		result.SizeOfImage = binary.LittleEndian.Uint32(data[56:60])
		result.SizeOfHeaders = binary.LittleEndian.Uint32(data[60:64])
		result.NumberOfRvaAndSizes = binary.LittleEndian.Uint32(data[92:96])
		directoryOffset = 96
	case OptionalMagicPE32Plus:
		if len(data) < 112 {
			return OptionalHeader{}, &ParseError{Offset: fileOffset, Context: "PE32+ optional header", Err: errors.New("truncated fixed fields")}
		}
		result.AddressOfEntryPoint = binary.LittleEndian.Uint32(data[16:20])
		result.ImageBase = binary.LittleEndian.Uint64(data[24:32])
		result.SectionAlignment = binary.LittleEndian.Uint32(data[32:36])
		result.FileAlignment = binary.LittleEndian.Uint32(data[36:40])
		result.SizeOfImage = binary.LittleEndian.Uint32(data[56:60])
		result.SizeOfHeaders = binary.LittleEndian.Uint32(data[60:64])
		result.NumberOfRvaAndSizes = binary.LittleEndian.Uint32(data[108:112])
		directoryOffset = 112
	default:
		return OptionalHeader{}, &ParseError{Offset: fileOffset, Context: "optional header magic", Err: fmt.Errorf("invalid value %#x", result.Magic)}
	}
	availableDirectories := (len(data) - directoryOffset) / 8
	if uint64(result.NumberOfRvaAndSizes) > uint64(availableDirectories) {
		return OptionalHeader{}, &ParseError{Offset: fileOffset + directoryOffset, Context: "data directories", Err: fmt.Errorf("declared count %d exceeds optional-header capacity %d", result.NumberOfRvaAndSizes, availableDirectories)}
	}
	result.DataDirectories = make([]DataDirectory, int(result.NumberOfRvaAndSizes))
	for index := range result.DataDirectories {
		offset := directoryOffset + index*8
		result.DataDirectories[index] = DataDirectory{
			VirtualAddress: binary.LittleEndian.Uint32(data[offset : offset+4]),
			Size:           binary.LittleEndian.Uint32(data[offset+4 : offset+8]),
		}
	}
	return result, nil
}

func (o *Object) parseImports() error {
	directory, ok := o.OptionalHeader.Directory(DirectoryImport)
	if !ok || directory.VirtualAddress == 0 {
		return nil
	}
	terminated := false
	// Crystal Palace walks until the zero descriptor instead of trusting the
	// directory's advisory Size field. RVA bounds and this hard record limit
	// keep that compatibility behavior safe.
	for index := 0; index < maxImportDescriptors; index++ {
		rva64 := uint64(directory.VirtualAddress) + uint64(index)*importDescriptorSize
		if rva64 > math.MaxUint32 {
			return &ParseError{Context: "import directory", Err: errors.New("descriptor RVA overflow")}
		}
		raw, fileOffset, err := o.bytesAtRVA(uint32(rva64), importDescriptorSize)
		if err != nil {
			return &ParseError{Offset: fileOffset, Context: fmt.Sprintf("import descriptor %d", index), Err: err}
		}
		descriptor := &ImportDescriptor{
			OriginalFirstThunk: binary.LittleEndian.Uint32(raw[:4]),
			TimeDateStamp:      binary.LittleEndian.Uint32(raw[4:8]),
			ForwarderChain:     binary.LittleEndian.Uint32(raw[8:12]),
			NameRVA:            binary.LittleEndian.Uint32(raw[12:16]),
			FirstThunk:         binary.LittleEndian.Uint32(raw[16:20]),
		}
		// Crystal Palace treats a zero Name RVA as the terminator.
		if descriptor.NameRVA == 0 {
			terminated = true
			break
		}
		descriptor.Name, _, err = o.stringAtRVA(descriptor.NameRVA)
		if err != nil {
			return &ParseError{Context: fmt.Sprintf("import descriptor %d module name", index), Err: err}
		}
		if descriptor.FirstThunk == 0 {
			return &ParseError{Context: fmt.Sprintf("import descriptor %d", index), Err: errors.New("FirstThunk is zero")}
		}
		descriptor.Imports, err = o.parseThunkTable(descriptor)
		if err != nil {
			return fmt.Errorf("pe: import descriptor %d (%s): %w", index, descriptor.Name, err)
		}
		o.Descriptors = append(o.Descriptors, descriptor)
		o.Imports = append(o.Imports, descriptor.Imports...)
	}
	if !terminated {
		return &ParseError{Context: "import directory", Err: errors.New("descriptor table has no terminator within declared bounds")}
	}
	return nil
}

func (o *Object) parseThunkTable(descriptor *ImportDescriptor) ([]*Import, error) {
	width := uint32(4)
	if o.OptionalHeader.Is64() {
		width = 8
	}
	result := make([]*Import, 0)
	for index := uint32(0); index < maxImportThunks; index++ {
		rva64 := uint64(descriptor.FirstThunk) + uint64(index)*uint64(width)
		if rva64 > math.MaxUint32 {
			return nil, errors.New("thunk RVA overflow")
		}
		raw, _, err := o.bytesAtRVA(uint32(rva64), int(width))
		if err != nil {
			return nil, fmt.Errorf("thunk %d: %w", index, err)
		}
		var value uint64
		if width == 8 {
			value = binary.LittleEndian.Uint64(raw)
		} else {
			value = uint64(binary.LittleEndian.Uint32(raw))
		}
		if value == 0 {
			return result, nil
		}
		entry := &Import{Address: uint32(rva64), Module: descriptor.Name}
		ordinalFlag := uint64(0x80000000)
		if width == 8 {
			ordinalFlag = uint64(1) << 63
		}
		// Accept the proper PE32+ high-bit flag and Crystal Palace's historical
		// low-dword interpretation when the upper dword is otherwise zero.
		legacy64Ordinal := width == 8 && value>>32 == 0 && value&(uint64(1)<<31) != 0
		if value&ordinalFlag != 0 || legacy64Ordinal {
			entry.ByOrdinal = true
			entry.Ordinal = uint16(value)
		} else {
			if value > math.MaxUint32 {
				return nil, fmt.Errorf("thunk %d import-by-name RVA %#x exceeds 32 bits", index, value)
			}
			byName, _, err := o.bytesAtRVA(uint32(value), 2)
			if err != nil {
				return nil, fmt.Errorf("thunk %d import hint: %w", index, err)
			}
			entry.Hint = binary.LittleEndian.Uint16(byName)
			entry.Function, _, err = o.stringAtRVA(uint32(value) + 2)
			if err != nil {
				return nil, fmt.Errorf("thunk %d import name: %w", index, err)
			}
		}
		result = append(result, entry)
	}
	return nil, errors.New("thunk table exceeds safety limit without a terminator")
}

func (o *Object) bytesAtRVA(rva uint32, size int) ([]byte, int, error) {
	if size < 0 {
		return nil, 0, errors.New("negative read size")
	}
	if rva < o.OptionalHeader.SizeOfHeaders {
		start := uint64(rva)
		end := start + uint64(size)
		if end <= uint64(len(o.file)) && end <= uint64(o.OptionalHeader.SizeOfHeaders) {
			return o.file[start:end], int(start), nil
		}
	}
	for _, section := range o.Sections {
		span := section.VirtualSize
		if section.SizeOfRawData > span {
			span = section.SizeOfRawData
		}
		if rva < section.VirtualAddress || uint64(rva) >= uint64(section.VirtualAddress)+uint64(span) {
			continue
		}
		delta := uint64(rva - section.VirtualAddress)
		if delta+uint64(size) > uint64(section.SizeOfRawData) {
			return nil, int(uint64(section.PointerToRawData) + delta), errors.New("RVA resolves into virtual padding or beyond raw section data")
		}
		fileOffset := uint64(section.PointerToRawData) + delta
		if fileOffset+uint64(size) > uint64(len(o.file)) {
			return nil, int(minU64(fileOffset, uint64(len(o.file)))), errors.New("RVA-backed bytes extend beyond file")
		}
		return o.file[fileOffset : fileOffset+uint64(size)], int(fileOffset), nil
	}
	return nil, 0, fmt.Errorf("RVA %#x does not map to a section", rva)
}

func (o *Object) stringAtRVA(rva uint32) (string, int, error) {
	_, fileOffset, err := o.bytesAtRVA(rva, 1)
	if err != nil {
		return "", fileOffset, err
	}
	for length := 0; length < 1<<20; length++ {
		currentRVA := uint64(rva) + uint64(length)
		if currentRVA > math.MaxUint32 {
			return "", fileOffset, errors.New("string RVA overflow")
		}
		value, currentOffset, err := o.bytesAtRVA(uint32(currentRVA), 1)
		if err != nil {
			return "", currentOffset, err
		}
		if value[0] == 0 {
			start, _, err := o.bytesAtRVA(rva, length)
			if err != nil {
				return "", fileOffset, err
			}
			return string(start), fileOffset, nil
		}
	}
	return "", fileOffset, errors.New("string exceeds safety limit without a terminator")
}

func cString(data []byte) string {
	for index, value := range data {
		if value == 0 {
			return string(data[:index])
		}
	}
	return string(data)
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
