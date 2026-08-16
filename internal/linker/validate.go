// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

// validateCOFFModel protects the linker APIs from malformed programmatically
// constructed models. Parsed objects already satisfy these invariants, but the
// linker is also intentionally usable by tests and higher-level builders.
func validateCOFFModel(object *coff.Object, stage string) error {
	if object == nil {
		return &Error{Stage: stage, Err: errors.New("nil object")}
	}
	sections := make(map[*coff.Section]struct{}, len(object.Sections))
	sectionNames := make(map[string]struct{}, len(object.Sections))
	for sectionIndex, section := range object.Sections {
		if section == nil {
			return &Error{Stage: stage, Err: fmt.Errorf("section %d is nil", sectionIndex)}
		}
		if section.Name == "" {
			return &Error{Stage: stage, Err: fmt.Errorf("section %d has an empty name", sectionIndex)}
		}
		if _, exists := sectionNames[section.Name]; exists {
			return &Error{Stage: stage, Section: section.Name, Err: errors.New("duplicate section name")}
		}
		if section.Object != object {
			return &Error{Stage: stage, Section: section.Name, Err: errors.New("section owner does not match object")}
		}
		sections[section] = struct{}{}
		sectionNames[section.Name] = struct{}{}
		for relocationIndex, relocation := range section.Relocations {
			if relocation == nil {
				return &Error{Stage: stage, Section: section.Name, Err: fmt.Errorf("relocation %d is nil", relocationIndex)}
			}
			if relocation.Section != section {
				return &Error{Stage: stage, Section: section.Name, Relocation: relocation, Err: errors.New("relocation parent does not match containing section")}
			}
			if relocation.SymbolName == "" {
				return &Error{Stage: stage, Section: section.Name, Relocation: relocation, Err: errors.New("relocation symbol name is empty")}
			}
			if uint64(relocation.VirtualAddress)+4 > uint64(len(section.Data)) {
				return &Error{Stage: stage, Section: section.Name, Relocation: relocation, Err: errors.New("relocation patch site is outside section data")}
			}
		}
	}
	symbolNames := make(map[string]struct{}, len(object.Symbols))
	for symbolIndex, symbol := range object.Symbols {
		if symbol == nil {
			return &Error{Stage: stage, Err: fmt.Errorf("symbol %d is nil", symbolIndex)}
		}
		if symbol.Name == "" {
			return &Error{Stage: stage, Err: fmt.Errorf("symbol %d has an empty name", symbolIndex)}
		}
		if _, exists := symbolNames[symbol.Name]; exists {
			return &Error{Stage: stage, Err: fmt.Errorf("duplicate symbol name %q", symbol.Name)}
		}
		if symbol.Section != nil {
			if _, exists := sections[symbol.Section]; !exists {
				return &Error{Stage: stage, Err: fmt.Errorf("symbol %q refers to a section outside its object", symbol.Name)}
			}
		}
		symbolNames[symbol.Name] = struct{}{}
	}
	return nil
}
