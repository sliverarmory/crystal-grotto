// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package ised

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
)

// ErrReencoderUnavailable marks edits that require the Iced-equivalent
// relocation-aware lift/rebuild/lower pipeline.
var ErrReencoderUnavailable = errors.New("ised: relocation-aware instruction re-encoder is unavailable")

// RewriteBackend applies a selected plan to Apply's private object clone. The
// complete semantic program is supplied so a future encoder can repair every
// affected instruction, branch, symbol, relocation, and unwind range.
type RewriteBackend interface {
	RewriteISED(*coff.Object, Program, Plan) error
}

// RewriteBackendFunc adapts a function to RewriteBackend.
type RewriteBackendFunc func(*coff.Object, Program, Plan) error

func (f RewriteBackendFunc) RewriteISED(object *coff.Object, program Program, plan Plan) error {
	return f(object, program, plan)
}

// Apply plans, clones, rewrites, and COFF-round-trips an object. The input is
// never mutated, including when semantic validation or a backend fails.
func Apply(object *coff.Object, program Program, configuration Configuration, options PlanOptions, backend RewriteBackend) (*coff.Object, Plan, error) {
	plan, err := BuildPlan(program, configuration, options)
	if err != nil {
		return nil, Plan{}, err
	}
	if object == nil {
		return nil, plan, fmt.Errorf("%w: nil COFF object", ErrInvalidProgram)
	}
	if object.Machine != program.Machine {
		return nil, plan, fmt.Errorf("%w: semantic machine %s differs from object machine %s", ErrInvalidProgram, program.Machine, object.Machine)
	}
	if len(plan.Edits) != 0 {
		if err := validateObjectProgram(object, program); err != nil {
			return nil, plan, err
		}
		if backend == nil {
			return nil, plan, ErrReencoderUnavailable
		}
	}
	candidate, err := cloneObject(object)
	if err != nil {
		return nil, plan, fmt.Errorf("ised: clone input: %w", err)
	}
	if len(plan.Edits) != 0 {
		if err := backend.RewriteISED(candidate, cloneProgram(program), clonePlan(plan)); err != nil {
			return nil, plan, fmt.Errorf("ised: rewrite: %w", err)
		}
	}
	validated, err := cloneObject(candidate)
	if err != nil {
		return nil, plan, fmt.Errorf("ised: validate rewritten COFF: %w", err)
	}
	return validated, clonePlan(plan), nil
}

func cloneObject(object *coff.Object) (*coff.Object, error) {
	raw, err := coffwrite.Marshal(object)
	if err != nil {
		return nil, err
	}
	return coff.Parse(raw)
}

func validateObjectProgram(object *coff.Object, program Program) error {
	for _, function := range program.Functions {
		section := object.GetSection(function.Section)
		if section == nil {
			return fmt.Errorf("%w: function %s references missing section %s", ErrInvalidProgram, function.Name, function.Section)
		}
		if !section.IsExecutable() {
			return fmt.Errorf("%w: function %s section %s is not executable", ErrInvalidProgram, function.Name, function.Section)
		}
		for index, instruction := range function.Instructions {
			end := uint64(instruction.Offset) + uint64(len(instruction.Bytes))
			if end > uint64(len(section.Data)) {
				return fmt.Errorf("%w: %s instruction %d exceeds section %s", ErrInvalidProgram, function.Name, index, function.Section)
			}
			if !bytes.Equal(section.Data[instruction.Offset:uint32(end)], instruction.Bytes) {
				return fmt.Errorf("%w: %s instruction %d bytes differ from section %s at %#x", ErrInvalidProgram, function.Name, index, function.Section, instruction.Offset)
			}
			hasRelocation := false
			for relocationIndex, relocation := range section.Relocations {
				if relocation == nil {
					return fmt.Errorf("%w: section %s relocation %d is nil", ErrInvalidProgram, function.Section, relocationIndex)
				}
				if relocation.VirtualAddress >= instruction.Offset && uint64(relocation.VirtualAddress) < end {
					hasRelocation = true
				}
			}
			if hasRelocation != instruction.HasRelocation {
				return fmt.Errorf("%w: %s instruction %d relocation analysis is stale", ErrInvalidProgram, function.Name, index)
			}
		}
	}
	return nil
}

// FixedBackend applies only edits whose complete emitted byte sequence has the
// same length as the original instruction. This preserves every object offset
// and therefore requires no branch or metadata repair.
type FixedBackend struct{}

var _ RewriteBackend = FixedBackend{}

func (FixedBackend) RewriteISED(object *coff.Object, _ Program, plan Plan) error {
	if object == nil {
		return fmt.Errorf("%w: nil COFF object", ErrInvalidProgram)
	}
	patches := make([]fixedPatch, 0, len(plan.Edits))
	for _, edit := range plan.Edits {
		section := object.GetSection(edit.Section)
		if section == nil {
			return fmt.Errorf("%w: missing section %s", ErrInvalidProgram, edit.Section)
		}
		emitted := renderEdit(edit)
		if len(emitted) != len(edit.Original.Bytes) {
			return &BoundaryError{
				Function: edit.Function, Section: edit.Section, Offset: edit.Original.Offset,
				Feature: "length-changing instruction rewrite", Err: ErrReencoderUnavailable,
			}
		}
		end := uint64(edit.Original.Offset) + uint64(len(edit.Original.Bytes))
		if end > uint64(len(section.Data)) || !bytes.Equal(section.Data[edit.Original.Offset:uint32(end)], edit.Original.Bytes) {
			return fmt.Errorf("%w: source instruction changed at %s+%#x", ErrInvalidProgram, edit.Section, edit.Original.Offset)
		}
		patches = append(patches, fixedPatch{section: section, offset: edit.Original.Offset, data: emitted})
	}
	// All validation precedes mutation, including every length boundary.
	for _, patch := range patches {
		copy(patch.section.Data[patch.offset:], patch.data)
	}
	return nil
}

type fixedPatch struct {
	section *coff.Section
	offset  uint32
	data    []byte
}

func renderEdit(edit Edit) []byte {
	var result []byte
	if edit.Prepend != nil {
		result = append(result, edit.Prepend.Content...)
	}
	if edit.Replace != nil {
		result = append(result, edit.Replace.Content...)
	} else {
		result = append(result, edit.Original.Bytes...)
	}
	if edit.Append != nil {
		result = append(result, edit.Append.Content...)
	}
	return result
}
