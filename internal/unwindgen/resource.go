// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package unwindgen

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

// ExportPhase documents the upstream order surrounding generated unwind data.
type ExportPhase string

const (
	PhaseTransform         ExportPhase = "normalize-and-transform"
	PhaseGenerateUnwind    ExportPhase = "generate-pdata-xdata"
	PhaseDiagnostics       ExportPhase = "diagnostics"
	PhasePatches           ExportPhase = "patches"
	PhaseLinkPostResources ExportPhase = "linkpost-unwind-resources"
	PhasePICOResource      ExportPhase = "pico-cpl-unwind"
	PhaseFinalExport       ExportPhase = "final-export"
)

// ExportOrder returns a defensive copy of Crystal Palace's unwind-sensitive
// export phases.
func ExportOrder() []ExportPhase {
	return []ExportPhase{
		PhaseTransform, PhaseGenerateUnwind, PhaseDiagnostics, PhasePatches,
		PhaseLinkPostResources, PhasePICOResource, PhaseFinalExport,
	}
}

// BuildResource combines generated pdata and xdata as two length-prefixed
// resource records while preserving and rebasing their relocations. Use an
// arbitrary linkpost symbol name for PIC or ".cpl_unwind" for PICO.
func BuildResource(name string, generated Result) (*coff.Section, error) {
	return BuildResourceSections(name, generated.PDATA, generated.XDATA)
}

// BuildResourceSections is the section-level form of BuildResource.
func BuildResourceSections(name string, pdata, xdata *coff.Section) (*coff.Section, error) {
	if name == "" {
		return nil, wrap("resource construction", "", 0, false, errors.New("resource name is empty"))
	}
	if pdata == nil || pdata.Name != ".pdata" || xdata == nil || xdata.Name != ".xdata" {
		return nil, wrap("resource construction", "", 0, false, errors.New("generated .pdata and .xdata sections are required"))
	}
	if uint64(len(pdata.Data)) > math.MaxUint32 || uint64(len(xdata.Data)) > math.MaxUint32 {
		return nil, wrap("resource construction", "", 0, false, errors.New("resource component exceeds 32 bits"))
	}
	if len(pdata.Data)%12 != 0 {
		return nil, wrap("resource construction", "", 0, false, errors.New("generated .pdata length is not a multiple of 12"))
	}
	if err := validateResourceComponent(pdata); err != nil {
		return nil, wrap("resource construction", "", 0, false, err)
	}
	if err := validateResourceComponent(xdata); err != nil {
		return nil, wrap("resource construction", "", 0, false, err)
	}
	pdataBase64 := alignOffset(4, sectionAlignment(pdata))
	xdataLengthHeader := pdataBase64 + uint64(len(pdata.Data))
	xdataBase64 := alignOffset(xdataLengthHeader+4, sectionAlignment(xdata))
	total := xdataBase64 + uint64(len(xdata.Data))
	if total > math.MaxUint32 {
		return nil, wrap("resource construction", "", 0, false, errors.New("combined unwind resource exceeds 32 bits"))
	}
	data := binary.LittleEndian.AppendUint32(nil, uint32(len(pdata.Data)))
	data = alignBytes(data, sectionAlignment(pdata))
	pdataBase := uint32(pdataBase64)
	data = append(data, pdata.Data...)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(xdata.Data)))
	data = alignBytes(data, sectionAlignment(xdata))
	xdataBase := uint32(xdataBase64)
	data = append(data, xdata.Data...)
	resource := coff.NewSection(name, data)
	resource.Alignment = 4

	appendRelocations := func(source *coff.Section, base uint32) error {
		for index, relocation := range source.Relocations {
			if relocation == nil {
				return fmt.Errorf("section %s relocation %d is nil", source.Name, index)
			}
			address := uint64(base) + uint64(relocation.VirtualAddress)
			if address > math.MaxUint32 {
				return fmt.Errorf("section %s relocation %d address overflows", source.Name, index)
			}
			cloned := *relocation
			cloned.Section = resource
			cloned.VirtualAddress = uint32(address)
			targetBase, internal := uint32(0), false
			switch {
			case relocation.Symbol != nil && relocation.Symbol.IsSectionName() && relocation.Symbol.Section == pdata,
				relocation.SymbolName == ".pdata":
				targetBase, internal = pdataBase, true
			case relocation.Symbol != nil && relocation.Symbol.IsSectionName() && relocation.Symbol.Section == xdata,
				relocation.SymbolName == ".xdata":
				targetBase, internal = xdataBase, true
			}
			if internal {
				if cloned.Type != coff.RelAMD64Addr32NB || uint64(cloned.VirtualAddress)+4 > uint64(len(resource.Data)) {
					return fmt.Errorf("internal resource relocation at %#x is not a valid ADDR32NB field", cloned.VirtualAddress)
				}
				value := binary.LittleEndian.Uint32(resource.Data[cloned.VirtualAddress : cloned.VirtualAddress+4])
				if uint64(value)+uint64(targetBase) > math.MaxUint32 {
					return fmt.Errorf("internal resource relocation at %#x overflows", cloned.VirtualAddress)
				}
				binary.LittleEndian.PutUint32(resource.Data[cloned.VirtualAddress:cloned.VirtualAddress+4], value+targetBase)
				cloned.SymbolName = name
				cloned.Symbol = nil
			}
			resource.Relocations = append(resource.Relocations, &cloned)
		}
		return nil
	}
	if err := appendRelocations(pdata, pdataBase); err != nil {
		return nil, wrap("resource construction", "", 0, false, err)
	}
	if err := appendRelocations(xdata, xdataBase); err != nil {
		return nil, wrap("resource construction", "", 0, false, err)
	}
	resource.SizeOfRawData = uint32(len(resource.Data))
	return resource, nil
}

func validateResourceComponent(section *coff.Section) error {
	if sectionAlignment(section) != 4 {
		return fmt.Errorf("generated section %s alignment is %d, want 4", section.Name, sectionAlignment(section))
	}
	for index, relocation := range section.Relocations {
		if relocation == nil {
			return fmt.Errorf("section %s relocation %d is nil", section.Name, index)
		}
		if relocation.Section != section {
			return fmt.Errorf("section %s relocation %d has a different parent section", section.Name, index)
		}
		if relocation.Type != coff.RelAMD64Addr32NB {
			return fmt.Errorf("section %s relocation %d has type %#x, want AMD64_ADDR32NB", section.Name, index, relocation.Type)
		}
		if relocation.SymbolName == "" {
			return fmt.Errorf("section %s relocation %d has no symbol name", section.Name, index)
		}
		if uint64(relocation.VirtualAddress)+4 > uint64(len(section.Data)) {
			return fmt.Errorf("section %s relocation %d is outside its data", section.Name, index)
		}
	}
	return nil
}

func sectionAlignment(section *coff.Section) uint32 {
	if section.Alignment == 0 {
		return 1
	}
	return section.Alignment
}

func alignBytes(data []byte, alignment uint32) []byte {
	if alignment <= 1 {
		return data
	}
	remainder := uint32(len(data)) % alignment
	if remainder == 0 {
		return data
	}
	return append(data, make([]byte, alignment-remainder)...)
}

func alignOffset(value uint64, alignment uint32) uint64 {
	if alignment <= 1 {
		return value
	}
	remainder := value % uint64(alignment)
	if remainder == 0 {
		return value
	}
	return value + uint64(alignment) - remainder
}
