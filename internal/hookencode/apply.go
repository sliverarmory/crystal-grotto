// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package hookencode

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
)

// Apply plans and applies hook rewrites to a private COFF clone. The source
// object and immutable model are never mutated, including on cancellation or
// any validation/encoding failure. A successful result has also completed a
// COFF marshal/parse round trip.
func Apply(ctx context.Context, object *coff.Object, model *hooks.Model) (*coff.Object, Plan, error) {
	plan, err := BuildPlan(ctx, object, model)
	if err != nil {
		return nil, Plan{}, err
	}
	candidate, err := cloneObject(object)
	if err != nil {
		return nil, plan, fmt.Errorf("hookencode: clone input: %w", err)
	}
	if err := applyPlan(ctx, candidate, plan); err != nil {
		return nil, plan, err
	}
	validated, err := cloneObject(candidate)
	if err != nil {
		return nil, plan, fmt.Errorf("hookencode: validate rewritten COFF: %w", err)
	}
	return validated, clonePlan(plan), nil
}

func cloneObject(object *coff.Object) (*coff.Object, error) {
	encoded, err := coffwrite.Marshal(object)
	if err != nil {
		return nil, err
	}
	return coff.Parse(encoded)
}

type plannedRelocation struct {
	siteIndex int
	site      Site
}

func applyPlan(ctx context.Context, object *coff.Object, plan Plan) error {
	if ctx == nil {
		return ErrNilContext
	}
	if object == nil {
		return ErrNilObject
	}
	if object.Machine != plan.Machine {
		return fmt.Errorf("%w: plan machine %s differs from object machine %s", ErrInvalidPlan, plan.Machine, object.Machine)
	}
	bySection := make(map[*coff.Section]map[int]plannedRelocation)
	spans := make(map[*coff.Section][][2]uint32)

	for index, site := range plan.Sites {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("hookencode: apply plan: %w", err)
		}
		fail := func(err error) error {
			return &SiteError{
				Pass: site.Pass, Section: site.SectionName, Relocation: site.RelocationIndex,
				Offset: site.InstructionOffset, Symbol: site.Symbol, Err: err,
			}
		}
		if site.SectionIndex < 0 || site.SectionIndex >= len(object.Sections) {
			return fail(fmt.Errorf("%w: section index %d is out of range", ErrInvalidPlan, site.SectionIndex))
		}
		section := object.Sections[site.SectionIndex]
		if section == nil || section.Name != site.SectionName {
			return fail(fmt.Errorf("%w: section identity changed", ErrInvalidPlan))
		}
		if site.InstructionLength == 0 || len(site.Original) != int(site.InstructionLength) || len(site.Replacement) != int(site.InstructionLength) {
			return fail(fmt.Errorf("%w: replacement is not length preserving", ErrInvalidPlan))
		}
		end := uint64(site.InstructionOffset) + uint64(site.InstructionLength)
		if end > uint64(len(section.Data)) {
			return fail(fmt.Errorf("%w: instruction exceeds section bounds", ErrInvalidPlan))
		}
		if !bytes.Equal(section.Data[site.InstructionOffset:uint32(end)], site.Original) {
			return fail(fmt.Errorf("%w: source instruction changed", ErrInvalidPlan))
		}
		for _, span := range spans[section] {
			if site.InstructionOffset < span[1] && span[0] < uint32(end) {
				return fail(fmt.Errorf("%w: rewrite overlaps site %d", ErrInvalidPlan, index))
			}
		}
		spans[section] = append(spans[section], [2]uint32{site.InstructionOffset, uint32(end)})

		if site.RelocationIndex < 0 {
			if site.action != relocationKeep {
				return fail(fmt.Errorf("%w: relocation-free site has a relocation action", ErrInvalidPlan))
			}
			copy(section.Data[site.InstructionOffset:uint32(end)], site.Replacement)
			continue
		}
		if site.RelocationIndex >= len(section.Relocations) {
			return fail(fmt.Errorf("%w: relocation index %d is out of range", ErrInvalidPlan, site.RelocationIndex))
		}
		relocation := section.Relocations[site.RelocationIndex]
		if relocation == nil || relocation.VirtualAddress != site.RelocationOffset || relocation.SymbolName != site.originalSymbol || relocation.Type != site.originalType {
			return fail(fmt.Errorf("%w: relocation identity changed", ErrInvalidPlan))
		}
		if _, duplicate := bySection[section][site.RelocationIndex]; duplicate {
			return fail(fmt.Errorf("%w: relocation is rewritten more than once", ErrInvalidPlan))
		}
		if bySection[section] == nil {
			bySection[section] = make(map[int]plannedRelocation)
		}
		bySection[section][site.RelocationIndex] = plannedRelocation{siteIndex: index, site: site}
		copy(section.Data[site.InstructionOffset:uint32(end)], site.Replacement)
	}

	for section, rewrites := range bySection {
		relocations := make([]*coff.Relocation, 0, len(section.Relocations))
		for index, relocation := range section.Relocations {
			rewrite, found := rewrites[index]
			if !found {
				relocations = append(relocations, relocation)
				continue
			}
			site := rewrite.site
			if site.writeAddend {
				if uint64(site.RelocationOffset)+4 > uint64(len(section.Data)) {
					return fmt.Errorf("%w: site %d relocation addend exceeds section", ErrInvalidPlan, rewrite.siteIndex)
				}
				binary.LittleEndian.PutUint32(section.Data[site.RelocationOffset:site.RelocationOffset+4], site.resultAddend)
			}
			switch site.action {
			case relocationConsume:
				continue
			case relocationRetarget:
				target := object.GetSymbol(site.resultSymbol)
				if target == nil {
					return fmt.Errorf("%w: site %d result symbol %q is missing", ErrInvalidPlan, rewrite.siteIndex, site.resultSymbol)
				}
				relocation.Section = section
				relocation.Symbol = target
				relocation.SymbolName = target.Name
				relocation.Type = site.resultType
				relocations = append(relocations, relocation)
			default:
				return fmt.Errorf("%w: site %d has invalid relocation action", ErrInvalidPlan, rewrite.siteIndex)
			}
		}
		section.Relocations = relocations
	}
	return nil
}
