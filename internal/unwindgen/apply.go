// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package unwindgen

import (
	"context"
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
)

// Apply generates and transactionally replaces .pdata and .xdata. No field of
// object changes unless generation, staging, and relocation rebinding all
// succeed.
func Apply(ctx context.Context, object *coff.Object, snapshot hooks.Snapshot, options Options) (Result, error) {
	objectMu.Lock()
	defer objectMu.Unlock()
	result, err := generate(ctx, object, snapshot, options)
	if err != nil {
		return Result{}, err
	}
	installed, err := replaceSections(object, result.PDATA, result.XDATA)
	if err != nil {
		return Result{}, err
	}
	result.PDATA = installed[".pdata"]
	result.XDATA = installed[".xdata"]
	return result, nil
}

// InstallResource transactionally adds or replaces a resource returned by
// BuildResource. PICO callers use this for .cpl_unwind after patches; PIC
// linkpost callers normally keep the resource as a linked section instead.
func InstallResource(object *coff.Object, resource *coff.Section) (*coff.Section, error) {
	objectMu.Lock()
	defer objectMu.Unlock()
	if resource == nil || resource.Name == "" {
		return nil, wrap("resource install", "", 0, false, errors.New("nil resource or empty resource name"))
	}
	installed, err := replaceSections(object, resource)
	if err != nil {
		return nil, err
	}
	return installed[resource.Name], nil
}

func replaceSections(object *coff.Object, replacements ...*coff.Section) (map[string]*coff.Section, error) {
	if object == nil {
		return nil, wrap("transaction staging", "", 0, false, errors.New("nil COFF object"))
	}
	replaceNames := make(map[string]bool, len(replacements))
	for _, section := range replacements {
		if section == nil || section.Name == "" {
			return nil, wrap("transaction staging", "", 0, false, errors.New("nil replacement or empty replacement name"))
		}
		if replaceNames[section.Name] {
			return nil, wrap("transaction staging", "", 0, false, fmt.Errorf("duplicate replacement section %q", section.Name))
		}
		replaceNames[section.Name] = true
	}

	staged, err := coff.NewObject(object.Machine)
	if err != nil {
		return nil, wrap("transaction staging", "", 0, false, err)
	}
	staged.TimeDateStamp = object.TimeDateStamp
	staged.Characteristics = object.Characteristics
	staged.OptionalHeader = append([]byte(nil), object.OptionalHeader...)

	sectionMap := make(map[*coff.Section]*coff.Section, len(object.Sections))
	for _, old := range object.Sections {
		if old == nil {
			return nil, wrap("transaction staging", "", 0, false, errors.New("object contains a nil section"))
		}
		if replaceNames[old.Name] {
			continue
		}
		cloned := cloneSectionHeader(old)
		if err := staged.AddSection(cloned); err != nil {
			return nil, wrap("transaction staging", "", 0, false, err)
		}
		sectionMap[old] = cloned
	}
	installed := make(map[string]*coff.Section, len(replacements))
	for _, replacement := range replacements {
		cloned := cloneSectionHeader(replacement)
		if err := staged.AddSection(cloned); err != nil {
			return nil, wrap("transaction staging", "", 0, false, err)
		}
		installed[cloned.Name] = cloned
	}

	symbolMap := make(map[*coff.Symbol]*coff.Symbol, len(object.Symbols))
	for _, old := range object.Symbols {
		if old == nil {
			return nil, wrap("transaction staging", "", 0, false, errors.New("object contains a nil symbol"))
		}
		if old.IsSectionName() {
			if mapped := sectionMap[old.Section]; mapped != nil {
				symbolMap[old] = staged.GetSymbol(mapped.Name)
			}
			continue
		}
		if old.Section != nil && sectionMap[old.Section] == nil {
			continue
		}
		cloned := &coff.Symbol{
			Name: old.Name, Value: old.Value, SectionNumber: old.SectionNumber,
			Type: old.Type, StorageClass: old.StorageClass, RawIndex: old.RawIndex,
		}
		for _, auxiliary := range old.AuxiliaryRecords {
			cloned.AuxiliaryRecords = append(cloned.AuxiliaryRecords, append([]byte(nil), auxiliary...))
		}
		if old.Section != nil {
			cloned.Section = sectionMap[old.Section]
		}
		if err := staged.AddSymbol(cloned); err != nil {
			return nil, wrap("transaction staging", old.Name, old.Value, old.Section != nil && old.Section.Name == ".text", err)
		}
		symbolMap[old] = cloned
	}

	for old, cloned := range sectionMap {
		if err := cloneRelocations(staged, old.Relocations, cloned, symbolMap); err != nil {
			return nil, err
		}
	}
	for _, replacement := range replacements {
		if err := cloneRelocations(staged, replacement.Relocations, installed[replacement.Name], symbolMap); err != nil {
			return nil, err
		}
	}

	// Section.Object and relocation.Section must identify the caller-visible
	// object after the atomic value replacement, not the temporary stage.
	for _, section := range staged.Sections {
		section.Object = object
		for _, relocation := range section.Relocations {
			relocation.Section = section
		}
	}
	*object = *staged
	return installed, nil
}

func cloneRelocations(staged *coff.Object, source []*coff.Relocation, target *coff.Section, symbols map[*coff.Symbol]*coff.Symbol) error {
	for index, relocation := range source {
		if relocation == nil {
			return wrap("transaction staging", "", 0, false, fmt.Errorf("section %q relocation %d is nil", target.Name, index))
		}
		cloned := &coff.Relocation{
			Section: target, VirtualAddress: relocation.VirtualAddress,
			SymbolTableIndex: relocation.SymbolTableIndex, SymbolName: relocation.SymbolName, Type: relocation.Type,
		}
		if relocation.Symbol != nil {
			cloned.Symbol = symbols[relocation.Symbol]
		}
		if cloned.Symbol == nil && cloned.SymbolName != "" {
			cloned.Symbol = staged.GetSymbol(cloned.SymbolName)
		}
		if cloned.Symbol != nil && cloned.SymbolName != "" && cloned.Symbol.Name != cloned.SymbolName {
			return wrap("transaction staging", "", relocation.VirtualAddress, target.Name == ".text", fmt.Errorf("relocation name %q disagrees with symbol %q", cloned.SymbolName, cloned.Symbol.Name))
		}
		target.Relocations = append(target.Relocations, cloned)
	}
	return nil
}

func cloneSection(section *coff.Section) *coff.Section {
	if section == nil {
		return nil
	}
	cloned := cloneSectionHeader(section)
	for _, relocation := range section.Relocations {
		if relocation == nil {
			cloned.Relocations = append(cloned.Relocations, nil)
			continue
		}
		copy := *relocation
		copy.Section = cloned
		cloned.Relocations = append(cloned.Relocations, &copy)
	}
	return cloned
}

func cloneSectionHeader(section *coff.Section) *coff.Section {
	return &coff.Section{
		Name: section.Name, OriginalName: section.OriginalName,
		VirtualSize: section.VirtualSize, VirtualAddress: section.VirtualAddress,
		SizeOfRawData: section.SizeOfRawData, PointerToRawData: section.PointerToRawData,
		PointerToRelocations: section.PointerToRelocations, PointerToLineNumbers: section.PointerToLineNumbers,
		NumberOfLineNumbers: section.NumberOfLineNumbers, Characteristics: section.Characteristics,
		Data: append([]byte(nil), section.Data...), Alignment: section.Alignment,
	}
}
