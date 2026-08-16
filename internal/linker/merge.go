// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

var primaryGroups = [...]string{".text", ".rdata", ".data", ".bss"}

// Merge combines compatible objects using Crystal Palace's section grouping,
// COMDAT folding, dependency walk, and same-section REL32 resolution.
func Merge(objects ...*coff.Object) (*coff.Object, error) {
	if len(objects) == 0 || objects[0] == nil {
		return nil, &Error{Stage: "merge", Err: errors.New("no input objects")}
	}
	machine := objects[0].Machine
	if machine != coff.MachineI386 && machine != coff.MachineAMD64 {
		return nil, &Error{Stage: "merge", Err: fmt.Errorf("unsupported machine %s", machine)}
	}
	for index, object := range objects {
		if object == nil {
			return nil, &Error{Stage: "merge", Err: fmt.Errorf("input object %d is nil", index)}
		}
		if object.Machine != machine {
			return nil, &Error{Stage: "merge", Err: fmt.Errorf("machine mismatch: object 0 is %s, object %d is %s", machine, index, object.Machine)}
		}
		if err := validateCOFFModel(object, "merge validation"); err != nil {
			return nil, err
		}
	}

	definitions := make(map[string]*coff.Symbol)
	folded := make(map[*coff.Section]bool)
	activeObjects := make([]*coff.Object, 0, len(objects))
	for _, object := range objects {
		// COFFList.exists skips a later object when all of its external
		// definitions are already represented. Require at least one definition
		// to avoid the upstream method's vacuous-empty-object trap.
		if objectAlreadyRepresented(object, definitions) {
			continue
		}
		activeObjects = append(activeObjects, object)
		for _, section := range object.Sections {
			if shouldFold(section, definitions) {
				folded[section] = true
				continue
			}
			for _, symbol := range section.SymbolsSorted() {
				if !symbol.IsExternal() || symbol.IsUndefined() {
					continue
				}
				if previous := definitions[symbol.Name]; previous != nil && previous != symbol {
					return nil, &Error{Stage: "merge", Section: section.Name, Err: fmt.Errorf("duplicate external symbol %q", symbol.Name)}
				}
				definitions[symbol.Name] = symbol
			}
		}
	}

	groups := make(map[string][]*coff.Section)
	groupOrder := append([]string(nil), primaryGroups[:]...)
	knownGroup := map[string]bool{".text": true, ".rdata": true, ".data": true, ".bss": true}
	seen := make(map[*coff.Section]bool)
	var visit func(*coff.Section)
	visit = func(section *coff.Section) {
		if section == nil || seen[section] {
			return
		}
		seen[section] = true
		if folded[section] {
			return
		}
		group := section.GroupName()
		if !knownGroup[group] {
			knownGroup[group] = true
			groupOrder = append(groupOrder, group)
		}
		groups[group] = append(groups[group], section)
		for _, relocation := range section.Relocations {
			if definition := definitions[relocation.SymbolName]; definition != nil {
				visit(definition.Section)
			} else {
				visit(relocation.RemoteSection())
			}
		}
	}
	for _, group := range primaryGroups {
		for _, object := range activeObjects {
			for _, section := range object.Sections {
				if section.Name == ".rdata$zzz" || section.GroupName() != group {
					continue
				}
				visit(section)
			}
		}
	}

	result, err := coff.NewObject(machine)
	if err != nil {
		return nil, &Error{Stage: "merge", Err: err}
	}
	baseBySection := make(map[*coff.Section]uint32)
	mergedBySection := make(map[*coff.Section]*coff.Section)
	for _, group := range groupOrder {
		entries := make([]layoutEntry, 0, len(groups[group]))
		for _, section := range groups[group] {
			entries = append(entries, layoutEntry{section: section})
		}
		layout, err := makeLayout(entries)
		if err != nil {
			return nil, &Error{Stage: "merge layout", Section: group, Err: err}
		}
		merged := coff.NewSection(group, layout.Bytes)
		if len(groups[group]) > 0 {
			// Upstream creates conventional flags from the group name. Preserve
			// an unusual group's first input flags instead of discarding them.
			if group != ".text" && group != ".rdata" && group != ".data" && group != ".bss" {
				merged.Characteristics = groups[group][0].Characteristics
			}
		}
		if err := result.AddSection(merged); err != nil {
			return nil, &Error{Stage: "merge section", Section: group, Err: err}
		}
		for _, placement := range layout.Placements {
			baseBySection[placement.Section] = placement.Offset
			mergedBySection[placement.Section] = merged
		}
	}

	oldToNew := make(map[*coff.Symbol]*coff.Symbol)
	for _, group := range groupOrder {
		merged := result.GetSection(group)
		for _, section := range groups[group] {
			base := baseBySection[section]
			for _, symbol := range section.SymbolsSorted() {
				value, err := checkedAdd32(base, symbol.Value)
				if err != nil {
					return nil, &Error{Stage: "merge symbol", Section: section.Name, Err: fmt.Errorf("symbol %q: %w", symbol.Name, err)}
				}
				cloned := &coff.Symbol{
					Name:             symbol.Name,
					Value:            value,
					SectionNumber:    int16(sectionIndex(result, merged) + 1),
					Type:             symbol.Type,
					StorageClass:     symbol.StorageClass,
					AuxiliaryRecords: cloneRecords(symbol.AuxiliaryRecords),
					Section:          merged,
				}
				if err := result.AddSymbol(cloned); err != nil {
					return nil, &Error{Stage: "merge symbol", Section: section.Name, Err: err}
				}
				oldToNew[symbol] = cloned
			}
		}
	}

	undefined := make(map[string]*coff.Symbol)
	for _, group := range groupOrder {
		merged := result.GetSection(group)
		for _, section := range groups[group] {
			sourceBase := baseBySection[section]
			for _, relocation := range section.Relocations {
				virtualAddress, err := checkedAdd32(sourceBase, relocation.VirtualAddress)
				if err != nil {
					return nil, &Error{Stage: "merge relocation", Section: section.Name, Relocation: relocation, Err: err}
				}
				cloned := &coff.Relocation{Section: merged, VirtualAddress: virtualAddress, Type: relocation.Type, SymbolName: relocation.SymbolName}
				if relocation.Symbol != nil && relocation.Symbol.IsSectionName() && relocation.RemoteSection() != nil {
					remote := relocation.RemoteSection()
					remoteMerged := mergedBySection[remote]
					if remoteMerged == nil {
						return nil, &Error{Stage: "merge relocation", Section: section.Name, Relocation: relocation, Err: fmt.Errorf("referenced section %q was not selected", remote.Name)}
					}
					cloned.SymbolName = remoteMerged.Name
					cloned.Symbol = result.GetSymbol(remoteMerged.Name)
					addend, err := relocation.Offset()
					if err != nil {
						return nil, &Error{Stage: "merge relocation", Section: section.Name, Relocation: relocation, Err: err}
					}
					adjusted := int64(addend) + int64(baseBySection[remote])
					if adjusted < math.MinInt32 || adjusted > math.MaxUint32 {
						return nil, &Error{Stage: "merge relocation", Section: section.Name, Relocation: relocation, Err: errors.New("section-relative addend exceeds 32 bits")}
					}
					if err := putUint32(merged.Data, virtualAddress, uint32(adjusted)); err != nil {
						return nil, &Error{Stage: "merge relocation", Section: merged.Name, Relocation: cloned, Err: err}
					}
				} else {
					var target *coff.Symbol
					if definition := definitions[relocation.SymbolName]; definition != nil {
						target = oldToNew[definition]
					}
					if target == nil && relocation.Symbol != nil {
						target = oldToNew[relocation.Symbol]
					}
					if target == nil {
						target = undefined[relocation.SymbolName]
						if target == nil {
							target = &coff.Symbol{Name: relocation.SymbolName, Type: symbolType(relocation.Symbol), StorageClass: coff.SymbolClassExternal}
							if err := result.AddSymbol(target); err != nil {
								return nil, &Error{Stage: "merge undefined symbol", Section: section.Name, Relocation: relocation, Err: err}
							}
							undefined[target.Name] = target
						}
					}
					cloned.Symbol = target
					cloned.SymbolName = target.Name
				}
				merged.Relocations = append(merged.Relocations, cloned)
			}
		}
	}

	if err := resolveSameSectionRelocations(result); err != nil {
		return nil, err
	}
	return result, nil
}

func objectAlreadyRepresented(object *coff.Object, definitions map[string]*coff.Symbol) bool {
	count := 0
	for _, section := range object.Sections {
		for _, symbol := range section.SymbolsSorted() {
			if !symbol.IsExternal() || symbol.IsUndefined() {
				continue
			}
			count++
			if definitions[symbol.Name] == nil {
				return false
			}
		}
	}
	return count != 0
}

func shouldFold(section *coff.Section, definitions map[string]*coff.Symbol) bool {
	if section == nil || !section.IsCOMDAT() {
		return false
	}
	for _, symbol := range section.SymbolsSorted() {
		if !symbol.IsExternal() || symbol.IsUndefined() {
			continue
		}
		other := definitions[symbol.Name]
		if other == nil || other == symbol || !symbol.FoldsWith(other) {
			return false
		}
	}
	return true
}

func resolveSameSectionRelocations(object *coff.Object) error {
	for _, section := range object.Sections {
		kept := section.Relocations[:0]
		for _, relocation := range section.Relocations {
			if relocation.Symbol == nil || relocation.Symbol.Section != section || !isRelative(object.Machine, relocation.Type) {
				kept = append(kept, relocation)
				continue
			}
			addend, err := relocation.Offset()
			if err != nil {
				return &Error{Stage: "resolve same-section relocation", Section: section.Name, Relocation: relocation, Err: err}
			}
			target := int64(relocation.Symbol.Value) + int64(addend)
			source := int64(relocation.VirtualAddress) + int64(relocation.FromOffset())
			delta := target - source
			if delta < math.MinInt32 || delta > math.MaxInt32 {
				return &Error{Stage: "resolve same-section relocation", Section: section.Name, Relocation: relocation, Err: errors.New("REL32 displacement is out of range")}
			}
			if err := putUint32(section.Data, relocation.VirtualAddress, uint32(int32(delta))); err != nil {
				return &Error{Stage: "resolve same-section relocation", Section: section.Name, Relocation: relocation, Err: err}
			}
		}
		section.Relocations = kept
	}
	return nil
}

func isRelative(machine coff.Machine, relocationType uint16) bool {
	if machine == coff.MachineAMD64 {
		return relocationType >= coff.RelAMD64Rel32 && relocationType <= coff.RelAMD64Rel32_5
	}
	return machine == coff.MachineI386 && relocationType == coff.RelI386Rel32
}

func sectionIndex(object *coff.Object, section *coff.Section) int {
	for index, candidate := range object.Sections {
		if candidate == section {
			return index
		}
	}
	return -1
}

func cloneRecords(records [][]byte) [][]byte {
	result := make([][]byte, len(records))
	for index := range records {
		result[index] = append([]byte(nil), records[index]...)
	}
	return result
}

func symbolType(symbol *coff.Symbol) uint16 {
	if symbol == nil {
		return 0
	}
	return symbol.Type
}

func putUint32(data []byte, offset uint32, value uint32) error {
	if uint64(offset)+4 > uint64(len(data)) {
		return fmt.Errorf("write at %#x exceeds %d-byte buffer", offset, len(data))
	}
	binary.LittleEndian.PutUint32(data[offset:offset+4], value)
	return nil
}

// LibraryMember is one archive/ZIP member. The linker does not parse archive
// containers; callers can parse members with coff.Parse and supply them here.
type LibraryMember struct {
	Name   string
	Object *coff.Object
}

// MergeLibrary selects members in input order when they define a currently
// unresolved relocation, repeating to a fixed point, then merges them.
func MergeLibrary(base *coff.Object, members []LibraryMember) (*coff.Object, []string, error) {
	if base == nil {
		return nil, nil, &Error{Stage: "library selection", Err: errors.New("nil base object")}
	}
	defined := definedNames(base)
	unresolved := unresolvedNames(base, defined)
	selected := make([]bool, len(members))
	var names []string
	objects := []*coff.Object{base}
	changed := true
	for changed {
		changed = false
		for index, member := range members {
			if selected[index] || member.Object == nil {
				continue
			}
			memberDefinitions := definedNames(member.Object)
			if !intersects(memberDefinitions, unresolved) {
				continue
			}
			selected[index] = true
			changed = true
			names = append(names, member.Name)
			objects = append(objects, member.Object)
			for name := range memberDefinitions {
				defined[name] = struct{}{}
				delete(unresolved, name)
			}
			for name := range unresolvedNames(member.Object, defined) {
				unresolved[name] = struct{}{}
			}
		}
	}
	merged, err := Merge(objects...)
	if err != nil {
		return nil, names, err
	}
	return merged, names, nil
}

func definedNames(object *coff.Object) map[string]struct{} {
	result := make(map[string]struct{})
	if object == nil {
		return result
	}
	for _, symbol := range object.Symbols {
		if symbol.IsExternal() && !symbol.IsUndefined() {
			result[symbol.Name] = struct{}{}
		}
	}
	return result
}

func unresolvedNames(object *coff.Object, defined map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{})
	if object == nil {
		return result
	}
	for _, section := range object.Sections {
		for _, relocation := range section.Relocations {
			if relocation.Symbol != nil && !relocation.Symbol.IsUndefined() {
				continue
			}
			if _, ok := defined[relocation.SymbolName]; !ok {
				result[relocation.SymbolName] = struct{}{}
			}
		}
	}
	return result
}

func intersects(left, right map[string]struct{}) bool {
	for value := range left {
		if _, ok := right[value]; ok {
			return true
		}
	}
	return false
}
