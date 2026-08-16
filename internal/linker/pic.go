// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"errors"
	"fmt"
	"math"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

type PICOptions struct {
	EntrySymbol  string
	RequireEntry bool
	Links        []LinkedSection

	// IncludeData and IncludeBSS extend upstream's raw-PIC default of .text,
	// optional .rdata, and explicitly linked content.
	IncludeData bool
	IncludeBSS  bool

	// X86RelativeDIR32 enables Crystal Palace's fixptrs-style interpretation
	// of I386_DIR32 as a relative displacement. Without it, raw PIC rejects
	// absolute x86 references because no runtime image base is known.
	X86RelativeDIR32 bool
}

type PICImage struct {
	Bytes       []byte
	Layout      *Layout
	EntryOffset uint32
	HasEntry    bool
}

// EmitPIC lays out and offline-fixes deterministic x86/x64 raw PIC content.
func EmitPIC(object *coff.Object, options PICOptions) (*PICImage, error) {
	if object == nil {
		return nil, &Error{Stage: "PIC", Err: errors.New("nil object")}
	}
	if err := validateCOFFModel(object, "PIC validation"); err != nil {
		return nil, err
	}
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return nil, &Error{Stage: "PIC", Err: fmt.Errorf("unsupported machine %s", object.Machine)}
	}
	text := object.GetSection(".text")
	if text == nil {
		return nil, &Error{Stage: "PIC", Err: errors.New("object has no .text section")}
	}
	entries := []layoutEntry{{section: text}}
	if section := object.GetSection(".rdata"); section != nil {
		// ProgramPIC64 is upstream's raw-PIC exporter for both x86 and x64.
		// It appends relocation-free .rdata in either architecture and rejects
		// all .rdata relocations because no runtime image base is available.
		if len(section.Relocations) != 0 {
			relocation := section.Relocations[0]
			detail := "suspected jump table; compile with -fno-jump-tables or equivalent"
			if object.Machine == coff.MachineAMD64 && relocation != nil && relocation.Type == coff.RelAMD64Addr64 {
				detail = "ADDR64 in .rdata cannot be resolved from raw PIC"
			}
			return nil, &Error{Stage: "PIC .rdata", Section: section.Name, Relocation: relocation, Err: errors.New(detail)}
		}
		entries = append(entries, layoutEntry{section: section})
	}
	if options.IncludeData {
		if section := object.GetSection(".data"); section != nil {
			entries = append(entries, layoutEntry{section: section})
		}
	}
	if options.IncludeBSS {
		if section := object.GetSection(".bss"); section != nil {
			entries = append(entries, layoutEntry{section: section})
		}
	}
	linkedByName := make(map[string]*coff.Section, len(options.Links))
	for _, linked := range options.Links {
		section, err := linked.section()
		if err != nil {
			return nil, &Error{Stage: "PIC link", Err: err}
		}
		if linkedByName[section.Name] != nil {
			return nil, &Error{Stage: "PIC link", Err: fmt.Errorf("duplicate linked name %q", section.Name)}
		}
		linkedByName[section.Name] = section
		entries = append(entries, layoutEntry{section: section})
	}
	layout, err := makeLayout(entries)
	if err != nil {
		return nil, &Error{Stage: "PIC layout", Err: err}
	}
	image := &PICImage{Bytes: append([]byte(nil), layout.Bytes...), Layout: layout}

	entryName := options.EntrySymbol
	if entryName == "" {
		entryName = defaultEntry(object.Machine)
	}
	if symbol := object.GetSymbol(entryName); symbol != nil && symbol.Section != nil {
		placement, ok := layout.Placement(symbol.Section)
		if !ok {
			return nil, &Error{Stage: "PIC entry", Err: fmt.Errorf("entry symbol %q is in an omitted section", entryName)}
		}
		entryOffset, err := checkedAdd32(placement.Offset, symbol.Value)
		if err != nil {
			return nil, &Error{Stage: "PIC entry", Err: err}
		}
		image.EntryOffset, image.HasEntry = entryOffset, true
		if entryOffset != 0 {
			return nil, &Error{Stage: "PIC entry", Err: fmt.Errorf("entry symbol %q is at %#x, not zero", entryName, entryOffset)}
		}
	} else if options.RequireEntry {
		return nil, &Error{Stage: "PIC entry", Err: fmt.Errorf("entry symbol %q was not found", entryName)}
	}

	for _, placement := range layout.Placements {
		for _, relocation := range placement.Section.Relocations {
			if relocation == nil {
				return nil, &Error{Stage: "PIC relocation", Section: placement.Section.Name, Err: errors.New("nil relocation")}
			}
			if err := applyPICRelocation(object, object.Machine, layout, image.Bytes, linkedByName, placement, relocation, options); err != nil {
				return nil, err
			}
		}
	}
	return image, nil
}

func applyPICRelocation(object *coff.Object, machine coff.Machine, layout *Layout, output []byte, linkedByName map[string]*coff.Section, source Placement, relocation *coff.Relocation, options PICOptions) error {
	patchOffset, err := checkedAdd32(source.Offset, relocation.VirtualAddress)
	if err != nil {
		return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: err}
	}
	if uint64(patchOffset)+4 > uint64(len(output)) {
		return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: errors.New("patch site is outside output")}
	}
	targetSection, targetSymbol, err := relocationTarget(object, layout, linkedByName, relocation)
	if err != nil {
		return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: err}
	}
	targetPlacement, _ := layout.Placement(targetSection)
	addend, err := relocation.Offset()
	if err != nil {
		return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: err}
	}
	target := int64(targetPlacement.Offset) + int64(addend)
	if targetSymbol != nil {
		target += int64(targetSymbol.Value)
	}

	switch {
	case machine == coff.MachineAMD64 && relocation.Type >= coff.RelAMD64Rel32 && relocation.Type <= coff.RelAMD64Rel32_5:
		delta := target - (int64(patchOffset) + int64(relocation.FromOffset()))
		if err := writeInt32(output, patchOffset, delta); err != nil {
			return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: err}
		}
	case machine == coff.MachineAMD64 && relocation.Type == coff.RelAMD64Addr32NB:
		if err := writeAbsolute32(output, patchOffset, target); err != nil {
			return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: err}
		}
	case machine == coff.MachineAMD64 && relocation.Type == coff.RelAMD64Addr64:
		return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: errors.New("AMD64_ADDR64 requires a runtime base and is not raw-PIC resolvable")}
	case machine == coff.MachineI386 && relocation.Type == coff.RelI386Rel32:
		delta := target - (int64(patchOffset) + 4)
		if err := writeInt32(output, patchOffset, delta); err != nil {
			return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: err}
		}
	case machine == coff.MachineI386 && relocation.Type == coff.RelI386Dir32:
		if !options.X86RelativeDIR32 {
			return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: errors.New("I386_DIR32 requires fixptrs/X86RelativeDIR32 for raw PIC")}
		}
		delta := target - (int64(patchOffset) + 4)
		if err := writeInt32(output, patchOffset, delta); err != nil {
			return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: err}
		}
	default:
		return &Error{Stage: "PIC relocation", Section: source.Section.Name, Relocation: relocation, Err: fmt.Errorf("unsupported relocation type %#x for %s", relocation.Type, machine)}
	}
	return nil
}

func relocationTarget(object *coff.Object, layout *Layout, linkedByName map[string]*coff.Section, relocation *coff.Relocation) (*coff.Section, *coff.Symbol, error) {
	if relocation.Symbol != nil && relocation.Symbol.Section != nil {
		if _, ok := layout.Placement(relocation.Symbol.Section); ok {
			return relocation.Symbol.Section, relocation.Symbol, nil
		}
	}
	if object != nil {
		if symbol := object.GetSymbol(relocation.SymbolName); symbol != nil && symbol.Section != nil {
			if _, ok := layout.Placement(symbol.Section); ok {
				return symbol.Section, symbol, nil
			}
		}
	}
	if linked := linkedByName[relocation.SymbolName]; linked != nil {
		if _, ok := layout.Placement(linked); ok {
			return linked, nil, nil
		}
	}
	return nil, nil, fmt.Errorf("unresolved or omitted symbol %q", relocation.SymbolName)
}

func writeInt32(output []byte, offset uint32, value int64) error {
	if value < math.MinInt32 || value > math.MaxInt32 {
		return fmt.Errorf("REL32 displacement %d is out of range", value)
	}
	return putUint32(output, offset, uint32(int32(value)))
}

func writeAbsolute32(output []byte, offset uint32, value int64) error {
	if value < 0 || value > math.MaxUint32 {
		return fmt.Errorf("absolute offset %d does not fit in uint32", value)
	}
	return putUint32(output, offset, uint32(value))
}
