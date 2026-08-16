// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

// Package linker implements Crystal Grotto's deterministic COFF merge,
// relocation, PIC, and PICO export core. Randomized BTF passes deliberately
// live above this package.
package linker

import (
	"errors"
	"fmt"
	"math"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

// Error identifies the linker stage and, when available, the section and
// relocation that caused the failure.
type Error struct {
	Stage      string
	Section    string
	Relocation *coff.Relocation
	Err        error
}

func (e *Error) Error() string {
	context := "linker"
	if e.Stage != "" {
		context += ": " + e.Stage
	}
	if e.Section != "" {
		context += " section " + e.Section
	}
	if e.Relocation != nil {
		context += fmt.Sprintf(" relocation at %#x to %q", e.Relocation.VirtualAddress, e.Relocation.SymbolName)
	}
	return context + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// LinkedRelocation is one relocation carried by generated linked content.
// Ordinary link/linkfunc byte blobs leave this slice empty. Post-link
// resources such as generated unwind information retain their ADDR32NB
// references through this representation.
type LinkedRelocation struct {
	VirtualAddress uint32
	SymbolName     string
	Type           uint16
}

// LinkedSection is content supplied by a spec link/linkfunc command or a
// generated post-link resource.
type LinkedSection struct {
	Name        string
	Data        []byte
	Executable  bool
	Alignment   uint32
	Relocations []LinkedRelocation
}

func (l LinkedSection) section() (*coff.Section, error) {
	if l.Name == "" {
		return nil, errors.New("linked section name is empty")
	}
	sectionName := ".rdata"
	if l.Executable {
		sectionName = ".text"
	}
	section := coff.NewSection(l.Name, l.Data)
	section.Characteristics = coff.FlagsForName(sectionName)
	section.Alignment = l.Alignment
	if section.Alignment == 0 {
		section.Alignment = 1
	}
	for index, linked := range l.Relocations {
		if linked.SymbolName == "" {
			return nil, fmt.Errorf("linked relocation %d has an empty symbol name", index)
		}
		if uint64(linked.VirtualAddress)+4 > uint64(len(section.Data)) {
			return nil, fmt.Errorf("linked relocation %d at %#x is outside %d-byte section", index, linked.VirtualAddress, len(section.Data))
		}
		section.Relocations = append(section.Relocations, &coff.Relocation{
			Section:        section,
			VirtualAddress: linked.VirtualAddress,
			SymbolName:     linked.SymbolName,
			Type:           linked.Type,
		})
	}
	return section, nil
}

// Placement describes one input section in a contiguous virtual region.
type Placement struct {
	Section *coff.Section
	Offset  uint32
	Size    uint32
	Sparse  bool
}

// Layout is a deterministic section layout. Bytes excludes sparse trailing
// BSS while VirtualSize includes it.
type Layout struct {
	Bytes       []byte
	VirtualSize uint32
	Placements  []Placement

	bySection map[*coff.Section]Placement
}

func (l *Layout) Placement(section *coff.Section) (Placement, bool) {
	if l == nil {
		return Placement{}, false
	}
	placement, ok := l.bySection[section]
	return placement, ok
}

// SectionPlacement returns the placement of the named section. It is useful
// for callers that supplied a LinkedSection and therefore do not own the
// linker-created section pointer.
func (l *Layout) SectionPlacement(name string) (Placement, bool) {
	if l == nil {
		return Placement{}, false
	}
	for _, placement := range l.Placements {
		if placement.Section != nil && placement.Section.Name == name {
			return placement, true
		}
	}
	return Placement{}, false
}

func (l *Layout) Offset(section *coff.Section) (uint32, bool) {
	placement, ok := l.Placement(section)
	return placement.Offset, ok
}

type layoutEntry struct {
	section *coff.Section
	sparse  bool
}

func makeLayout(entries []layoutEntry) (*Layout, error) {
	result := &Layout{bySection: make(map[*coff.Section]Placement, len(entries))}
	var virtual uint64
	var sparseSeen bool
	for _, entry := range entries {
		if entry.section == nil {
			continue
		}
		if sparseSeen {
			return nil, fmt.Errorf("section %q follows sparse BSS", entry.section.Name)
		}
		alignment := uint64(entry.section.Alignment)
		if alignment == 0 {
			alignment = 1
		}
		aligned, err := alignUp(virtual, alignment)
		if err != nil || aligned > math.MaxUint32 {
			return nil, fmt.Errorf("align section %q: size overflow", entry.section.Name)
		}
		if aligned > virtual {
			padding := aligned - virtual
			if padding > uint64(math.MaxInt-len(result.Bytes)) {
				return nil, fmt.Errorf("align section %q: allocation overflow", entry.section.Name)
			}
			result.Bytes = append(result.Bytes, make([]byte, int(padding))...)
			virtual = aligned
		}
		size := uint64(len(entry.section.Data))
		if virtual+size > math.MaxUint32 {
			return nil, fmt.Errorf("section %q makes layout exceed 32 bits", entry.section.Name)
		}
		placement := Placement{Section: entry.section, Offset: uint32(virtual), Size: uint32(size), Sparse: entry.sparse}
		result.Placements = append(result.Placements, placement)
		result.bySection[entry.section] = placement
		if entry.sparse {
			sparseSeen = true
		} else {
			result.Bytes = append(result.Bytes, entry.section.Data...)
		}
		virtual += size
	}
	result.VirtualSize = uint32(virtual)
	return result, nil
}

func alignUp(value, alignment uint64) (uint64, error) {
	if alignment == 0 {
		return 0, errors.New("alignment is zero")
	}
	remainder := value % alignment
	if remainder == 0 {
		return value, nil
	}
	delta := alignment - remainder
	if value > math.MaxUint64-delta {
		return 0, errors.New("alignment overflow")
	}
	return value + delta, nil
}

func defaultEntry(machine coff.Machine) string {
	if machine == coff.MachineI386 {
		return "_go"
	}
	return "go"
}

func checkedAdd32(values ...uint32) (uint32, error) {
	var total uint64
	for _, value := range values {
		total += uint64(value)
		if total > math.MaxUint32 {
			return 0, errors.New("32-bit offset overflow")
		}
	}
	return uint32(total), nil
}
