// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

// Package coff parses and models Microsoft COFF object files.
package coff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Machine is an IMAGE_FILE_MACHINE_* value.
type Machine uint16

const (
	MachineI386  Machine = 0x014c
	MachineAMD64 Machine = 0x8664
	MachineARM64 Machine = 0xaa64
)

func (m Machine) String() string {
	switch m {
	case MachineI386:
		return "x86"
	case MachineAMD64:
		return "x64"
	case MachineARM64:
		return "arm64"
	default:
		return fmt.Sprintf("unknown-0x%04x", uint16(m))
	}
}

// Valid reports whether Crystal Palace recognizes the machine value.
func (m Machine) Valid() bool {
	return m == MachineI386 || m == MachineAMD64 || m == MachineARM64
}

// Bits returns the native pointer width. Crystal Palace's executable
// transformation pipeline only supports the two Intel machines.
func (m Machine) Bits() (int, error) {
	switch m {
	case MachineI386:
		return 32, nil
	case MachineAMD64, MachineARM64:
		return 64, nil
	default:
		return 0, fmt.Errorf("coff: unsupported machine %#x", uint16(m))
	}
}

// ParseError identifies the file offset and structure that failed validation.
type ParseError struct {
	Offset  int
	Context string
	Err     error
}

func (e *ParseError) Error() string {
	if e.Context == "" {
		return fmt.Sprintf("coff: offset %#x: %v", e.Offset, e.Err)
	}
	return fmt.Sprintf("coff: %s at offset %#x: %v", e.Context, e.Offset, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// Object is a parsed or programmatically constructed COFF object. Sections and
// Symbols retain file order; lookup methods do not depend on map iteration.
type Object struct {
	Machine         Machine
	TimeDateStamp   uint32
	Characteristics uint16
	OptionalHeader  []byte
	Sections        []*Section
	Symbols         []*Symbol

	sectionsByName map[string]*Section
	symbolsByName  map[string]*Symbol
	rawSymbols     []*Symbol // includes nil slots occupied by auxiliary records
}

// NewObject constructs an empty object for a recognized machine.
func NewObject(machine Machine) (*Object, error) {
	if !machine.Valid() {
		return nil, fmt.Errorf("coff: unrecognized machine %#x", uint16(machine))
	}
	return &Object{
		Machine:        machine,
		sectionsByName: make(map[string]*Section),
		symbolsByName:  make(map[string]*Symbol),
	}, nil
}

func (o *Object) ensureIndexes() {
	if o.sectionsByName == nil {
		o.sectionsByName = make(map[string]*Section, len(o.Sections))
		for _, section := range o.Sections {
			if section != nil {
				o.sectionsByName[section.Name] = section
			}
		}
	}
	if o.symbolsByName == nil {
		o.symbolsByName = make(map[string]*Symbol, len(o.Symbols))
		for _, symbol := range o.Symbols {
			if symbol != nil {
				o.symbolsByName[symbol.Name] = symbol
			}
		}
	}
}

// Architecture returns the Crystal Palace architecture spelling.
func (o *Object) Architecture() string { return o.Machine.String() }

func (o *Object) IsIntel() bool { return o.Machine == MachineI386 || o.Machine == MachineAMD64 }
func (o *Object) IsX86() bool   { return o.Machine == MachineI386 }
func (o *Object) IsX64() bool   { return o.Machine == MachineAMD64 }

func (o *Object) Bits() (int, error) { return o.Machine.Bits() }

// GetSection returns a section by its normalized, object-unique name.
func (o *Object) GetSection(name string) *Section {
	o.ensureIndexes()
	return o.sectionsByName[name]
}

// GetSymbol returns a non-label symbol by its object-unique name.
func (o *Object) GetSymbol(name string) *Symbol {
	o.ensureIndexes()
	return o.symbolsByName[name]
}

// AddSection adds a section and its conventional static section symbol.
func (o *Object) AddSection(section *Section) error {
	if section == nil || section.Name == "" {
		return errors.New("coff: section name is empty")
	}
	o.ensureIndexes()
	if o.sectionsByName[section.Name] != nil {
		return fmt.Errorf("coff: section %q is already present", section.Name)
	}
	if o.symbolsByName[section.Name] != nil {
		return fmt.Errorf("coff: section %q conflicts with an existing symbol", section.Name)
	}
	section.Object = o
	o.Sections = append(o.Sections, section)
	o.sectionsByName[section.Name] = section
	return o.AddSymbol(NewSectionSymbol(section, section.Name))
}

// AddSymbol adds a symbol while preserving deterministic insertion order.
func (o *Object) AddSymbol(symbol *Symbol) error {
	if symbol == nil || symbol.Name == "" {
		return errors.New("coff: symbol name is empty")
	}
	o.ensureIndexes()
	if o.symbolsByName[symbol.Name] != nil {
		return fmt.Errorf("coff: duplicate symbol %q", symbol.Name)
	}
	o.Symbols = append(o.Symbols, symbol)
	o.symbolsByName[symbol.Name] = symbol
	return nil
}

// RemoveSymbols removes named symbols without disturbing the remaining order.
func (o *Object) RemoveSymbols(names map[string]struct{}) {
	kept := o.Symbols[:0]
	for _, symbol := range o.Symbols {
		if _, remove := names[symbol.Name]; remove {
			delete(o.symbolsByName, symbol.Name)
			continue
		}
		kept = append(kept, symbol)
	}
	o.Symbols = kept
}

// RemapSymbol renames a symbol and every relocation that refers to it.
func (o *Object) RemapSymbol(oldName, newName string) error {
	o.ensureIndexes()
	old := o.symbolsByName[oldName]
	if old == nil {
		return nil
	}
	if existing := o.symbolsByName[newName]; existing != nil && existing != old {
		compatibleUndefined := existing.Section == nil && existing.Type == old.Type && existing.Value == 0 && existing.StorageClass == SymbolClassExternal
		if !compatibleUndefined && (existing.Section != old.Section || existing.Type != old.Type || existing.StorageClass != old.StorageClass || existing.Value != old.Value) {
			return fmt.Errorf("coff: cannot remap %q to incompatible symbol %q", oldName, newName)
		}
		o.Symbols = removeSymbolPointer(o.Symbols, existing)
	}
	delete(o.symbolsByName, oldName)
	old.Name = newName
	o.symbolsByName[newName] = old
	for _, section := range o.Sections {
		for _, relocation := range section.Relocations {
			if relocation.SymbolName == oldName {
				relocation.SymbolName = newName
				relocation.Symbol = old
			}
		}
	}
	return nil
}

func removeSymbolPointer(symbols []*Symbol, remove *Symbol) []*Symbol {
	result := symbols[:0]
	for _, symbol := range symbols {
		if symbol != remove {
			result = append(result, symbol)
		}
	}
	return result
}

// Section models an IMAGE_SECTION_HEADER and its referenced contents.
type Section struct {
	Object               *Object
	Name                 string
	OriginalName         string
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfLineNumbers  uint16
	Characteristics      uint32
	Data                 []byte
	Relocations          []*Relocation
	Alignment            uint32
}

// NewSection creates an initialized, empty section with Crystal Palace's
// conventional characteristics for the supplied name.
func NewSection(name string, data []byte) *Section {
	return &Section{Name: name, OriginalName: name, Characteristics: FlagsForName(name), Data: append([]byte(nil), data...), SizeOfRawData: uint32(len(data)), Alignment: 1}
}

func (s *Section) GroupName() string {
	if index := strings.IndexByte(s.Name, '$'); index >= 0 {
		return s.Name[:index]
	}
	return s.Name
}

func (s *Section) IsUninitialized() bool { return HasFlag(s.Characteristics, SectionUninitializedData) }
func (s *Section) IsExecutable() bool    { return HasFlag(s.Characteristics, SectionMemExecute) }
func (s *Section) IsCOMDAT() bool        { return HasFlag(s.Characteristics, SectionLinkCOMDAT) }

// PageAlignedData mirrors Crystal Palace's historical behavior: a complete
// additional page is appended when Data is already page-aligned.
func (s *Section) PageAlignedData() []byte {
	padding := 4096 - len(s.Data)%4096
	result := make([]byte, len(s.Data)+padding)
	copy(result, s.Data)
	return result
}

func (s *Section) PagePadding() int { return 4096 - len(s.Data)%4096 }

func (s *Section) Patch(offset int, patch []byte) error {
	if offset < 0 || len(patch) > len(s.Data)-offset {
		return fmt.Errorf("coff: patch [%d,%d) is outside section %q (%d bytes)", offset, offset+len(patch), s.Name, len(s.Data))
	}
	copy(s.Data[offset:], patch)
	return nil
}

func (s *Section) Fetch(offset, length int) ([]byte, error) {
	if offset < 0 || length < 0 || length > len(s.Data)-offset {
		return nil, fmt.Errorf("coff: range [%d,%d) is outside section %q (%d bytes)", offset, offset+length, s.Name, len(s.Data))
	}
	return append([]byte(nil), s.Data[offset:offset+length]...), nil
}

// SymbolsSorted returns non-section-name symbols ordered by value, then name.
func (s *Section) SymbolsSorted() []*Symbol {
	if s.Object == nil {
		return nil
	}
	var result []*Symbol
	for _, symbol := range s.Object.Symbols {
		if symbol.Section == s && !symbol.IsSectionName() {
			result = append(result, symbol)
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Value != result[j].Value {
			return result[i].Value < result[j].Value
		}
		return result[i].Name < result[j].Name
	})
	return result
}

const (
	SymbolClassExternal uint8  = 2
	SymbolClassStatic   uint8  = 3
	SymbolClassLabel    uint8  = 6
	SymbolTypeFunction  uint16 = 0x20
)

// Symbol models an IMAGE_SYMBOL. AuxiliaryRecords does not include the primary
// record and RawIndex retains the original symbol-table index.
type Symbol struct {
	Name             string
	Value            uint32
	SectionNumber    int16
	Type             uint16
	StorageClass     uint8
	AuxiliaryRecords [][]byte
	RawIndex         uint32
	Section          *Section
}

func NewSectionSymbol(section *Section, name string) *Symbol {
	return &Symbol{Name: name, Section: section, Type: 0, StorageClass: SymbolClassStatic}
}

func NewDataSymbol(section *Section, name string, value uint32) *Symbol {
	return &Symbol{Name: name, Value: value, Section: section, StorageClass: SymbolClassExternal}
}

func NewFunctionSymbol(section *Section, name string, value uint32) *Symbol {
	return &Symbol{Name: name, Value: value, Section: section, Type: SymbolTypeFunction, StorageClass: SymbolClassExternal}
}

func (s *Symbol) IsUndefined() bool { return s.Section == nil }
func (s *Symbol) IsExternal() bool  { return s.StorageClass == SymbolClassExternal }
func (s *Symbol) IsFunction() bool  { return s.Type == SymbolTypeFunction }
func (s *Symbol) IsLabel() bool     { return s.StorageClass == SymbolClassLabel }
func (s *Symbol) IsGlobalVariable() bool {
	return s.IsExternal() && !s.IsFunction() && s.Section != nil
}

func (s *Symbol) IsSectionName() bool {
	if s == nil || s.Section == nil || s.StorageClass != SymbolClassStatic || s.Value != 0 {
		return false
	}
	return strings.HasPrefix(s.Name, ".") || s.Name == s.Section.Name
}

func (s *Symbol) FoldsWith(other *Symbol) bool {
	return other != nil && s.Name == other.Name && s.Type == other.Type && s.StorageClass == other.StorageClass
}

func (s *Symbol) EstimateSize() uint32 {
	if s == nil || s.Section == nil || s.Value > uint32(len(s.Section.Data)) {
		return 0
	}
	for _, next := range s.Section.SymbolsSorted() {
		if next.Value > s.Value {
			return next.Value - s.Value
		}
	}
	return uint32(len(s.Section.Data)) - s.Value
}

// Relocation models an IMAGE_RELOCATION and resolves its symbol-table slot.
type Relocation struct {
	Section          *Section
	VirtualAddress   uint32
	SymbolTableIndex uint32
	SymbolName       string
	Type             uint16
	Symbol           *Symbol
}

const (
	RelAMD64Addr64   uint16 = 0x0001
	RelAMD64Addr32NB uint16 = 0x0003
	RelAMD64Rel32    uint16 = 0x0004
	RelAMD64Rel32_1  uint16 = 0x0005
	RelAMD64Rel32_2  uint16 = 0x0006
	RelAMD64Rel32_3  uint16 = 0x0007
	RelAMD64Rel32_4  uint16 = 0x0008
	RelAMD64Rel32_5  uint16 = 0x0009
	RelI386Dir32     uint16 = 0x0006
	RelI386Rel32     uint16 = 0x0014
)

func (r *Relocation) IsAMD64Rel32() bool {
	return r != nil && r.Section != nil && r.Section.Object != nil && r.Section.Object.Machine == MachineAMD64 && r.Type >= RelAMD64Rel32 && r.Type <= RelAMD64Rel32_5
}

func (r *Relocation) FromOffset() uint32 {
	if r.IsAMD64Rel32() {
		return uint32(r.Type)
	}
	return 4
}

func (r *Relocation) RemoteSection() *Section {
	if r == nil || r.Symbol == nil {
		return nil
	}
	return r.Symbol.Section
}

func (r *Relocation) Offset() (int32, error) {
	if r == nil || r.Section == nil {
		return 0, errors.New("coff: relocation has no parent section")
	}
	address := uint64(r.VirtualAddress)
	if address+4 > uint64(len(r.Section.Data)) {
		return 0, fmt.Errorf("coff: relocation at %#x is outside section %q", r.VirtualAddress, r.Section.Name)
	}
	return int32(binary.LittleEndian.Uint32(r.Section.Data[address : address+4])), nil
}

func (r *Relocation) RemoteSectionOffset() (int64, error) {
	if r.Symbol == nil {
		return 0, fmt.Errorf("coff: relocation references missing symbol %q", r.SymbolName)
	}
	offset, err := r.Offset()
	if err != nil {
		return 0, err
	}
	return int64(offset) + int64(r.Symbol.Value), nil
}

// ContainingFunction mirrors Crystal Palace's diagnostic lookup behavior.
func (r *Relocation) ContainingFunction() *Symbol {
	if r == nil || r.Section == nil {
		return nil
	}
	var last *Symbol
	for _, symbol := range r.Section.SymbolsSorted() {
		if !symbol.IsFunction() {
			continue
		}
		if symbol.Value >= r.VirtualAddress {
			return last
		}
		last = symbol
	}
	return last
}

// Section flags translated from IMAGE_SCN_* values used by Crystal Palace.
const (
	SectionCode              uint32 = 0x00000020
	SectionInitializedData   uint32 = 0x00000040
	SectionUninitializedData uint32 = 0x00000080
	SectionLinkCOMDAT        uint32 = 0x00001000
	SectionMemExecute        uint32 = 0x20000000
	SectionMemRead           uint32 = 0x40000000
	SectionMemWrite          uint32 = 0x80000000
)

func HasFlag(flags, flag uint32) bool { return flags&flag == flag }

func FlagsForName(name string) uint32 {
	switch name {
	case ".text":
		return SectionCode | SectionMemExecute | SectionMemRead
	case ".rdata":
		return SectionInitializedData | SectionMemRead
	case ".data":
		return SectionInitializedData | SectionMemRead | SectionMemWrite
	case ".bss":
		return SectionUninitializedData | SectionMemRead | SectionMemWrite
	default:
		return SectionInitializedData | SectionMemRead
	}
}

func FormatSectionFlags(flags uint32) string {
	var access [3]byte
	access[0], access[1], access[2] = '-', '-', '-'
	if HasFlag(flags, SectionMemRead) {
		access[0] = 'r'
	}
	if HasFlag(flags, SectionMemWrite) {
		access[1] = 'w'
	}
	if HasFlag(flags, SectionMemExecute) {
		access[2] = 'x'
	}
	parts := []string{string(access[:])}
	if HasFlag(flags, SectionCode) {
		parts = append(parts, "(code)")
	}
	if HasFlag(flags, SectionInitializedData) {
		parts = append(parts, "(init)")
	}
	if HasFlag(flags, SectionUninitializedData) {
		parts = append(parts, "(not init)")
	}
	if HasFlag(flags, SectionLinkCOMDAT) {
		parts = append(parts, "(COMDAT)")
	}
	return strings.Join(parts, " ")
}
