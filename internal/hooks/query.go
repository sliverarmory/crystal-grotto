// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package hooks

import (
	"fmt"

	crystalimports "github.com/sliverarmory/crystal-grotto/internal/imports"
)

// IsPreserved reports whether target must remain unhooked in context.
func (m *Model) IsPreserved(target, context string) bool {
	return m != nil && m.preserve.contains(target, context)
}

// IsOptOut reports whether context opted out of a particular wrapper.
func (m *Model) IsOptOut(context, wrapper string) bool {
	return m != nil && m.optout.contains(context, wrapper)
}

func (m *Model) IsProtected(context string) bool {
	if m == nil {
		return false
	}
	_, present := m.protected[context]
	return present
}

func (m *Model) HasExternalHooks() bool { return m != nil && len(m.external.byTarget) > 0 }
func (m *Model) HasLocalHooks() bool    { return m != nil && len(m.local.byTarget) > 0 }

// ResolveExternal returns the attach wrapper selected for context and target.
func (m *Model) ResolveExternal(context, target string) (string, bool) {
	if m == nil {
		return "", false
	}
	return m.resolveChain(m.external, context, target)
}

// ResolveLocal returns the redirect wrapper selected for context and target.
func (m *Model) ResolveLocal(context, target string) (string, bool) {
	if m == nil {
		return "", false
	}
	return m.resolveChain(m.local, context, target)
}

func (m *Model) resolveChain(chains hookChains, context, target string) (string, bool) {
	chain, present := chains.byTarget[target]
	if !present {
		return "", false
	}
	type resolution struct {
		wrapper string
		found   bool
	}
	cache := make(map[string]resolution)
	visiting := make(map[string]bool)
	var resolve func(string) (string, bool)
	resolve = func(current string) (string, bool) {
		if value, ok := cache[current]; ok {
			return value.wrapper, value.found
		}
		if visiting[current] {
			return "", false
		}
		visiting[current] = true
		defer delete(visiting, current)

		if m.IsProtected(current) || m.IsPreserved(target, current) || target == current {
			cache[current] = resolution{}
			return "", false
		}
		for _, candidate := range chain {
			if candidate.Wrapper == current || m.IsOptOut(current, candidate.Wrapper) {
				continue
			}
			if declared := hookByWrapper(chain, current); declared != nil && declared.DeclaredIndex > candidate.DeclaredIndex {
				continue
			}

			allowed := true
			next, found := resolve(candidate.Wrapper)
			for found {
				if m.IsOptOut(current, next) {
					allowed = false
					break
				}
				next, found = resolve(next)
			}
			if allowed {
				value := resolution{wrapper: candidate.Wrapper, found: true}
				cache[current] = value
				return value.wrapper, true
			}
		}
		cache[current] = resolution{}
		return "", false
	}
	return resolve(context)
}

func hookByWrapper(chain []Hook, wrapper string) *Hook {
	for index := range chain {
		if chain[index].Wrapper == wrapper {
			return &chain[index]
		}
	}
	return nil
}

func (m *Model) PlanAttach(context, target string) HookPlan {
	wrapper, matched := m.ResolveExternal(context, target)
	return HookPlan{Kind: Attach, Context: context, Target: target, Wrapper: wrapper, Matched: matched, RequiresEncoder: matched}
}

// PlanAttachImport parses the relocation spelling consumed by the upstream
// Attach pass. Naked LoadLibraryA/GetProcAddress imports are attributed to
// KERNEL32; other naked imports retain the empty-module "$Function" target.
func (m *Model) PlanAttachImport(context, relocationSymbol string) HookPlan {
	imported, valid := crystalimports.ParseSymbol(relocationSymbol)
	if !valid {
		return HookPlan{Kind: Attach, Context: context}
	}
	module := imported.Module
	if module == "" && (imported.Function == "LoadLibraryA" || imported.Function == "GetProcAddress") {
		module = "KERNEL32"
	}
	return m.PlanAttach(context, module+"$"+imported.Function)
}

func (m *Model) PlanRedirect(context, target string) HookPlan {
	wrapper, matched := m.ResolveLocal(context, target)
	return HookPlan{Kind: Redirect, Context: context, Target: target, Wrapper: wrapper, Matched: matched, RequiresEncoder: matched}
}

// ResolveHooks returns addhook entries in deterministic declaration-key order.
// Upstream shuffles immediately before encoding; an encoder may shuffle this
// defensive slice with its injected random source.
func (m *Model) ResolveHooks() []ResolveHook {
	if m == nil {
		return nil
	}
	result := make([]ResolveHook, 0, len(m.resolve))
	for _, function := range m.resolveOrder {
		if entry, present := m.resolve[function]; present {
			result = append(result, entry)
		}
	}
	return result
}

// ResolveRegisteredHook applies addhook's explicit-wrapper/self precedence.
func (m *Model) ResolveRegisteredHook(context string, entry ResolveHook) (string, bool) {
	if !entry.Self {
		return entry.Wrapper, entry.Wrapper != ""
	}
	return m.ResolveExternal(context, entry.Target)
}

func (m *Model) CatchHandler(function string) (string, bool) {
	if m == nil {
		return "", false
	}
	handler, present := m.catches[function]
	return handler, present
}

// CatchEncodingError lets an export path fail explicitly until it has applied
// the configured handlers to x64 unwind metadata.
func (m *Model) CatchEncodingError() error {
	if m == nil {
		return ErrNilModel
	}
	if len(m.catches) == 0 {
		return nil
	}
	return fmt.Errorf("%w: regenerate x64 unwind metadata for catch", ErrEncoderRequired)
}

func (m *Model) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	result := Snapshot{
		Machine:      m.machine.String(),
		External:     snapshotChains(m.external),
		Local:        snapshotChains(m.local),
		Preserved:    snapshotSelections(m.preserve),
		OptOut:       snapshotSelections(m.optout),
		Protected:    append([]string(nil), m.protectedOrder...),
		ResolveHooks: m.ResolveHooks(),
	}
	for _, symbol := range m.intrinsicOrder {
		if content, present := m.intrinsics[symbol]; present {
			result.Intrinsics = append(result.Intrinsics, IntrinsicSnapshot{
				Symbol: symbol, Content: append([]byte(nil), content...),
			})
		}
	}
	for _, function := range m.catchOrder {
		if handler, present := m.catches[function]; present {
			result.Catches = append(result.Catches, CatchSnapshot{Function: function, Handler: handler})
		}
	}
	return result
}

func snapshotChains(chains hookChains) []HookChainSnapshot {
	result := make([]HookChainSnapshot, 0, len(chains.order))
	for _, target := range chains.order {
		result = append(result, HookChainSnapshot{
			Target: target, Hooks: append([]Hook(nil), chains.byTarget[target]...),
		})
	}
	return result
}

func snapshotSelections(values selections) []SelectionSnapshot {
	result := make([]SelectionSnapshot, 0, len(values.order))
	for _, target := range values.order {
		result = append(result, SelectionSnapshot{
			Target: target, Values: append([]string(nil), values.lists[target]...),
		})
	}
	return result
}
