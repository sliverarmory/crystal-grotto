// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

// Package pe implements the bounded PE parsing needed by Crystal Grotto.
package pe

import (
	"fmt"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

const (
	OptionalMagicPE32     uint16 = 0x010b
	OptionalMagicPE32Plus uint16 = 0x020b

	DirectoryExport        = 0
	DirectoryImport        = 1
	DirectoryResource      = 2
	DirectoryException     = 3
	DirectorySecurity      = 4
	DirectoryBaseReloc     = 5
	DirectoryDebug         = 6
	DirectoryArchitecture  = 7
	DirectoryGlobalPtr     = 8
	DirectoryTLS           = 9
	DirectoryLoadConfig    = 10
	DirectoryBoundImport   = 11
	DirectoryIAT           = 12
	DirectoryDelayImport   = 13
	DirectoryCOMDescriptor = 14
)

// ParseError identifies the PE structure and file offset that failed.
type ParseError struct {
	Offset  int
	Context string
	Err     error
}

func (e *ParseError) Error() string {
	if e.Context == "" {
		return fmt.Sprintf("pe: offset %#x: %v", e.Offset, e.Err)
	}
	return fmt.Sprintf("pe: %s at offset %#x: %v", e.Context, e.Offset, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type OptionalHeader struct {
	Magic               uint16
	AddressOfEntryPoint uint32
	ImageBase           uint64
	SectionAlignment    uint32
	FileAlignment       uint32
	SizeOfImage         uint32
	SizeOfHeaders       uint32
	NumberOfRvaAndSizes uint32
	DataDirectories     []DataDirectory
}

func (h OptionalHeader) Is64() bool { return h.Magic == OptionalMagicPE32Plus }

func (h OptionalHeader) Directory(index int) (DataDirectory, bool) {
	if index < 0 || index >= len(h.DataDirectories) {
		return DataDirectory{}, false
	}
	return h.DataDirectories[index], true
}

// Section retains both RVA layout and raw-file layout.
type Section struct {
	Name                 string
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
	Data                 []byte
}

// ImportDescriptor is an IMAGE_IMPORT_DESCRIPTOR and its decoded thunks.
type ImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	NameRVA            uint32
	FirstThunk         uint32
	Name               string
	Imports            []*Import
}

// Import is one IAT slot. Address is the RVA at which the loader writes the
// resolved function pointer.
type Import struct {
	Address   uint32
	Module    string
	Function  string
	Hint      uint16
	Ordinal   uint16
	ByOrdinal bool
}

func (i Import) String() string {
	if i.ByOrdinal {
		return fmt.Sprintf("Import %#x %s$(#%d)", i.Address, i.Module, i.Ordinal)
	}
	return fmt.Sprintf("Import %#x %s$%s", i.Address, i.Module, i.Function)
}

type Object struct {
	Machine         coff.Machine
	TimeDateStamp   uint32
	Characteristics uint16
	OptionalHeader  OptionalHeader
	Sections        []*Section
	Descriptors     []*ImportDescriptor
	Imports         []*Import

	file []byte
}

func (o *Object) Architecture() string { return o.Machine.String() }
func (o *Object) EntryPoint() uint32   { return o.OptionalHeader.AddressOfEntryPoint }

func (o *Object) GetSection(name string) *Section {
	for _, section := range o.Sections {
		if section.Name == name {
			return section
		}
	}
	return nil
}

// String renders a deterministic PE/import diagnostic.
func (o *Object) String() string {
	if o == nil {
		return "<nil PE object>\n"
	}
	var output strings.Builder
	fmt.Fprintf(&output, "PE\nMachine: %s\nEntryPoint: %#x\n", o.Architecture(), o.EntryPoint())
	fmt.Fprintf(&output, "Sections (%d):\n", len(o.Sections))
	for index, section := range o.Sections {
		fmt.Fprintf(&output, "  [%d] %s rva=%#x virtual=%d raw=%d characteristics=%#x\n", index, section.Name, section.VirtualAddress, section.VirtualSize, len(section.Data), section.Characteristics)
	}
	fmt.Fprintf(&output, "Imports (%d):\n", len(o.Imports))
	for index, imported := range o.Imports {
		fmt.Fprintf(&output, "  [%d] %s\n", index, imported.String())
	}
	return output.String()
}
