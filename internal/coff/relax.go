// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package coff

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const referencePointerPrefix = ".refptr."

// RelaxReport describes the x64 reference-pointer relaxations applied to an
// object. Removed names are sorted so diagnostics and tests are deterministic.
type RelaxReport struct {
	RelaxedRelocations int
	RemovedSections    []string
	RemovedSymbols     []string
}

type relaxation struct {
	section    *Section
	relocation *Relocation
	target     *Symbol
	refptr     *Symbol
}

// RelaxReferencePointers performs Crystal Palace's x64 .refptr relaxation.
// A matching `mov reg, [.refptr.symbol]` is changed to LEA and its REL32
// relocation is redirected to the real symbol. Refptr sections that become
// unreachable, and orphaned refptr sections, are removed.
//
// All matching instructions are validated before the object is mutated.
func RelaxReferencePointers(object *Object) (RelaxReport, error) {
	if object == nil {
		return RelaxReport{}, errors.New("coff: cannot relax a nil object")
	}
	if object.Machine != MachineAMD64 {
		return RelaxReport{}, errors.New("coff: +relax is x64 only")
	}

	plans := make([]relaxation, 0)
	for _, section := range object.Sections {
		if section == nil || !section.IsExecutable() {
			continue
		}
		for _, relocation := range section.Relocations {
			if relocation == nil || relocation.Type != RelAMD64Rel32 || !strings.HasPrefix(relocation.SymbolName, referencePointerPrefix) {
				continue
			}
			targetName := strings.TrimPrefix(relocation.SymbolName, referencePointerPrefix)
			target := object.GetSymbol(targetName)
			if target == nil {
				continue
			}
			address := uint64(relocation.VirtualAddress)
			if address < 3 || address+4 > uint64(len(section.Data)) {
				return RelaxReport{}, fmt.Errorf("coff: +relax relocation for %q at %#x is outside section %q", relocation.SymbolName, relocation.VirtualAddress, section.Name)
			}
			rex, opcode := section.Data[address-3], section.Data[address-2]
			if opcode != 0x8b || (rex != 0x48 && rex != 0x4c) {
				continue
			}
			refptr := object.GetSymbol(relocation.SymbolName)
			if refptr == nil {
				continue
			}
			if refptr.Section == nil {
				return RelaxReport{}, fmt.Errorf("coff: +relax symbol %q has no section", refptr.Name)
			}
			plans = append(plans, relaxation{section: section, relocation: relocation, target: target, refptr: refptr})
		}
	}

	garbage := make(map[string]struct{})
	for _, plan := range plans {
		plan.section.Data[plan.relocation.VirtualAddress-2] = 0x8d
		plan.relocation.SymbolName = plan.target.Name
		plan.relocation.Symbol = plan.target
		garbage[plan.refptr.Section.Name] = struct{}{}
	}

	seen := make(map[string]struct{})
	for _, section := range object.Sections {
		for _, relocation := range section.Relocations {
			if relocation == nil {
				continue
			}
			seen[relocation.SymbolName] = struct{}{}
			if remote := relocation.RemoteSection(); remote != nil {
				delete(garbage, remote.Name)
			}
		}
	}
	for _, section := range object.Sections {
		if !strings.HasPrefix(section.Name, ".rdata$.refptr.") {
			continue
		}
		symbolName := strings.TrimPrefix(section.Name, ".rdata$")
		if _, referenced := seen[symbolName]; !referenced {
			garbage[section.Name] = struct{}{}
		}
	}

	removeSymbols := make(map[string]struct{})
	for _, symbol := range object.Symbols {
		if symbol == nil || symbol.Section == nil {
			continue
		}
		if _, remove := garbage[symbol.Section.Name]; remove {
			removeSymbols[symbol.Name] = struct{}{}
		}
	}
	object.RemoveSymbols(removeSymbols)
	object.RemoveSections(garbage)

	report := RelaxReport{RelaxedRelocations: len(plans)}
	for name := range garbage {
		report.RemovedSections = append(report.RemovedSections, name)
	}
	for name := range removeSymbols {
		report.RemovedSymbols = append(report.RemovedSymbols, name)
	}
	sort.Strings(report.RemovedSections)
	sort.Strings(report.RemovedSymbols)
	return report, nil
}
