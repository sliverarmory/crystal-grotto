// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package resolver

import (
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
)

// ErrReencoderUnavailable indicates that a valid plan contains rewrites but no
// relocation-aware instruction encoder was supplied.
var ErrReencoderUnavailable = errors.New("resolver: instruction re-encoder is unavailable")

// RewriteBackend performs all planned rewrites on a private object clone. A
// backend may reorder/rebuild sections, but must remove or retarget every
// planned import relocation before returning success.
type RewriteBackend interface {
	RewriteResolvers(*coff.Object, RewritePlan) error
}

// RewriteBackendFunc adapts a function to RewriteBackend.
type RewriteBackendFunc func(*coff.Object, RewritePlan) error

func (f RewriteBackendFunc) RewriteResolvers(object *coff.Object, plan RewritePlan) error {
	return f(object, plan)
}

// Apply builds a plan, clones object, invokes backend, verifies every planned
// relocation was consumed, and round-trips the result through the COFF writer.
// The input object is never mutated, including when a backend fails midway.
func Apply(object *coff.Object, configuration Configuration, backend RewriteBackend) (*coff.Object, RewritePlan, error) {
	plan, err := BuildPlan(object, configuration)
	if err != nil {
		return nil, RewritePlan{}, err
	}
	if len(plan.Sites) != 0 && backend == nil {
		return nil, plan, ErrReencoderUnavailable
	}
	candidate, err := cloneObject(object)
	if err != nil {
		return nil, plan, fmt.Errorf("resolver: clone input: %w", err)
	}
	if len(plan.Sites) != 0 {
		backendPlan := clonePlan(plan)
		if err := backend.RewriteResolvers(candidate, backendPlan); err != nil {
			return nil, plan, fmt.Errorf("resolver: rewrite: %w", err)
		}
		if err := verifyConsumed(candidate, plan); err != nil {
			return nil, plan, err
		}
	}
	validated, err := cloneObject(candidate)
	if err != nil {
		return nil, plan, fmt.Errorf("resolver: validate rewritten COFF: %w", err)
	}
	return validated, clonePlan(plan), nil
}

func cloneObject(object *coff.Object) (*coff.Object, error) {
	data, err := coffwrite.Marshal(object)
	if err != nil {
		return nil, err
	}
	return coff.Parse(data)
}

func verifyConsumed(object *coff.Object, plan RewritePlan) error {
	for _, site := range plan.Sites {
		for _, section := range object.Sections {
			if section == nil || section.Name != site.SectionName {
				continue
			}
			for _, relocation := range section.Relocations {
				if relocation != nil && relocation.VirtualAddress == site.Offset && relocation.SymbolName == site.Symbol {
					return fmt.Errorf("resolver: backend left %s relocation at %s+%#x unresolved", site.Symbol, site.SectionName, site.Offset)
				}
			}
		}
	}
	return nil
}

func clonePlan(value RewritePlan) RewritePlan {
	result := RewritePlan{Machine: value.Machine, Sites: make([]Site, len(value.Sites))}
	for index, site := range value.Sites {
		result.Sites[index] = site
		result.Sites[index].Resolver = cloneResolver(site.Resolver)
		result.Sites[index].Invocation.ModuleString = cloneStringData(site.Invocation.ModuleString)
		result.Sites[index].Invocation.FunctionString = cloneStringData(site.Invocation.FunctionString)
	}
	return result
}

func cloneStringData(value StringData) StringData {
	return StringData{
		Bytes: append([]byte(nil), value.Bytes...), Words: append([]uint64(nil), value.Words...), PushOrder: append([]uint32(nil), value.PushOrder...),
	}
}
