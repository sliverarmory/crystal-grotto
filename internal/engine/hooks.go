// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package engine

import (
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	crystalhash "github.com/sliverarmory/crystal-grotto/internal/hash"
)

// hookEncodingFeatures reports only hook state that can change this object.
// Configuration-only directives remain useful no-ops until an applicable call
// site exists; applicable rewrites fail explicitly until the binary encoder is
// connected to the hook planner.
func (a *Artifact) hookEncodingFeatures(object *coff.Object) []string {
	if a == nil || a.config.hooks == nil || object == nil {
		return nil
	}
	features := make(map[string]struct{})
	for _, section := range object.Sections {
		for _, relocation := range section.Relocations {
			if relocation == nil {
				continue
			}
			context := ""
			if function := relocation.ContainingFunction(); function != nil {
				context = function.Name
			}
			if plan := a.config.hooks.PlanAttachImport(context, relocation.SymbolName); plan.Matched && plan.RequiresEncoder {
				features["attach"] = struct{}{}
			}
		}
	}
	if a.config.hooks.HasLocalHooks() {
		// Same-section call relocations are resolved during normalization, so a
		// complete local-reference scan requires the hook instruction encoder.
		features["redirect"] = struct{}{}
	}

	snapshot := a.config.hooks.Snapshot()
	userIntrinsics := make(map[string]struct{}, len(snapshot.Intrinsics))
	for _, intrinsic := range snapshot.Intrinsics {
		userIntrinsics[intrinsic.Symbol] = struct{}{}
	}
	for _, symbol := range object.Symbols {
		if symbol == nil {
			continue
		}
		name := symbol.Name
		_, user := userIntrinsics[name]
		if name == "__resolve_hook" || name == "___resolve_hook" ||
			strings.HasPrefix(name, "__tag_") || strings.HasPrefix(name, "___tag_") ||
			crystalhash.MatchesPrefix(name) || user {
			features["intrinsic"] = struct{}{}
		}
	}
	if len(snapshot.Catches) != 0 && a.hasOption("+unwind") {
		features["catch"] = struct{}{}
	}

	result := make([]string, 0, len(features))
	for feature := range features {
		result = append(result, feature)
	}
	sort.Strings(result)
	return result
}
