// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package hooks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/binutil"
	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/imports"
)

type hookChains struct {
	byTarget map[string][]Hook
	order    []string
}

type selections struct {
	values map[string]map[string]struct{}
	order  []string
	lists  map[string][]string
}

// Model is an immutable hook configuration.
type Model struct {
	machine coff.Machine
	nextID  int

	external hookChains
	local    hookChains
	preserve selections
	optout   selections

	protected      map[string]struct{}
	protectedOrder []string

	resolve      map[string]ResolveHook // keyed by function, as upstream
	resolveOrder []string

	intrinsics     map[string][]byte
	intrinsicOrder []string
	catches        map[string]string
	catchOrder     []string
}

// New creates the initial architecture-specific state. Crystal Palace
// implicitly protects its debug printer even when that symbol is absent.
func New(object *coff.Object) (*Model, error) {
	if object == nil {
		return nil, ErrNilObject
	}
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMachine, object.Machine)
	}
	debugSymbol := "_dprintf"
	if object.Machine == coff.MachineAMD64 {
		debugSymbol = "dprintf"
	}
	return &Model{
		machine:        object.Machine,
		external:       hookChains{byTarget: make(map[string][]Hook)},
		local:          hookChains{byTarget: make(map[string][]Hook)},
		preserve:       newSelections(),
		optout:         newSelections(),
		protected:      map[string]struct{}{debugSymbol: {}},
		protectedOrder: []string{debugSymbol},
		resolve:        make(map[string]ResolveHook),
		intrinsics:     make(map[string][]byte),
		catches:        make(map[string]string),
	}, nil
}

func newSelections() selections {
	return selections{
		values: make(map[string]map[string]struct{}),
		lists:  make(map[string][]string),
	}
}

func (m *Model) Machine() coff.Machine {
	if m == nil {
		return 0
	}
	return m.machine
}

// Apply validates and applies one parsed directive atomically.
func (m *Model) Apply(ctx context.Context, object *coff.Object, directive Directive, resolveBytes ByteResolver) (*Model, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if m == nil {
		return nil, ErrNilModel
	}
	if object == nil {
		return nil, ErrNilObject
	}
	if object.Machine != m.machine {
		return nil, fmt.Errorf("hooks: object machine %s differs from model machine %s", object.Machine, m.machine)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hooks: apply %s: %w", directive.kind, err)
	}
	if _, err := Parse(string(directive.kind), directive.arguments); err != nil {
		return nil, err
	}

	arguments := directive.arguments
	switch directive.kind {
	case Attach:
		if err := CheckFunction(object, arguments[1]); err != nil {
			return nil, err
		}
		if _, err := ParseModuleFunction(arguments[0]); err != nil {
			return nil, err
		}
		if chainHasWrapper(m.external.byTarget[arguments[0]], arguments[1]) {
			return nil, duplicateHookError(arguments[0], arguments[1])
		}
		result := m.clone()
		result.addHook(&result.external, arguments[0], arguments[1])
		return result, nil

	case Redirect:
		if err := CheckFunction(object, arguments[1]); err != nil {
			return nil, err
		}
		if chainHasWrapper(m.local.byTarget[arguments[0]], arguments[1]) {
			return nil, duplicateHookError(arguments[0], arguments[1])
		}
		result := m.clone()
		result.addHook(&result.local, arguments[0], arguments[1])
		return result, nil

	case Preserve:
		functions := binutil.SplitSet(arguments[1])
		for _, function := range functions {
			if err := CheckFunction(object, function); err != nil {
				return nil, err
			}
		}
		result := m.clone()
		result.preserve.add(arguments[0], functions)
		return result, nil

	case Protect:
		result := m.clone()
		for _, function := range binutil.SplitSet(arguments[0]) {
			result.addProtected(function)
		}
		return result, nil

	case OptOut:
		if err := CheckFunction(object, arguments[0]); err != nil {
			return nil, err
		}
		wrappers := binutil.SplitSet(arguments[1])
		for _, wrapper := range wrappers {
			if err := CheckFunction(object, wrapper); err != nil {
				return nil, err
			}
		}
		result := m.clone()
		result.optout.add(arguments[0], wrappers)
		return result, nil

	case AddHook:
		if len(arguments) == 2 {
			if err := CheckFunction(object, arguments[1]); err != nil {
				return nil, err
			}
		}
		parsed, err := ParseModuleFunction(arguments[0])
		if err != nil {
			return nil, err
		}
		entry := ResolveHook{
			Target: parsed.Target(), Module: parsed.Module, Function: parsed.Function,
			Self: len(arguments) == 1,
		}
		if len(arguments) == 2 {
			entry.Wrapper = arguments[1]
		}
		result := m.clone()
		result.addResolveHook(entry)
		return result, nil

	case FilterHooks:
		content, err := resolveDirectiveBytes(ctx, directive, resolveBytes)
		if err != nil {
			return nil, err
		}
		if len(content) < 2 {
			return nil, errors.New("Argument is not a COFF or DLL.")
		}
		magic := binary.LittleEndian.Uint16(content[:2])
		if magic != 0x5a4d && magic != uint16(coff.MachineI386) && magic != uint16(coff.MachineAMD64) {
			return nil, errors.New("Argument is not a COFF or DLL.")
		}
		parsed, err := imports.Parse(content)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("hooks: apply %s: %w", directive.kind, err)
		}
		allowed := make(map[string]struct{})
		for _, target := range parsed.Strings() {
			allowed[target] = struct{}{}
		}
		result := m.clone()
		result.filterResolveHooks(allowed)
		return result, nil

	case Intrinsic:
		prefix := "__"
		if m.machine == coff.MachineI386 {
			prefix = "___"
		}
		if len(arguments[0]) < len(prefix) || arguments[0][:len(prefix)] != prefix {
			return nil, fmt.Errorf("Intrinsic symbol %s must start with %s", arguments[0], prefix)
		}
		content, err := resolveDirectiveBytes(ctx, directive, resolveBytes)
		if err != nil {
			return nil, err
		}
		result := m.clone()
		result.addIntrinsic(arguments[0], content)
		return result, nil

	case Catch:
		if m.machine != coff.MachineAMD64 {
			return nil, errors.New("catch is x64-only")
		}
		function, handler := arguments[0], arguments[1]
		if err := CheckFunction(object, function); err != nil {
			return nil, err
		}
		if err := CheckFunction(object, handler); err != nil {
			return nil, err
		}
		if existing, present := m.catches[function]; present {
			return nil, fmt.Errorf("Handler %s already defined for %s", existing, function)
		}
		if existing, present := m.catches[handler]; present {
			return nil, fmt.Errorf("Handler %s has handler %s It cannot be a handler.", handler, existing)
		}
		if m.isCatchHandler(function) {
			return nil, fmt.Errorf("Function %s is a handler. We cannot associate a handler with it", function)
		}
		if function == handler {
			return nil, fmt.Errorf("Handler %s cannot handle exceptions for itself. That's a REALLY bad idea.", handler)
		}
		result := m.clone()
		result.catches[function] = handler
		result.catchOrder = append(result.catchOrder, function)
		return result, nil
	}
	return nil, fmt.Errorf("hooks: unsupported directive %q", directive.kind)
}

// ApplyResolved is a convenience for commands whose environment bytes have
// already been resolved. Content is defensively copied by Apply.
func (m *Model) ApplyResolved(ctx context.Context, object *coff.Object, directive Directive, content []byte) (*Model, error) {
	return m.Apply(ctx, object, directive, func(string) ([]byte, error) {
		return append([]byte(nil), content...), nil
	})
}

func resolveDirectiveBytes(ctx context.Context, directive Directive, resolver ByteResolver) ([]byte, error) {
	if resolver == nil {
		return nil, fmt.Errorf("hooks: %s requires a byte resolver for %s", directive.kind, directive.resourceRef)
	}
	content, err := resolver(directive.resourceRef)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("hooks: apply %s: %w", directive.kind, err)
	}
	return append([]byte(nil), content...), nil
}

func (m *Model) addHook(chains *hookChains, target, wrapper string) {
	if _, present := chains.byTarget[target]; !present {
		chains.order = append(chains.order, target)
	}
	chains.byTarget[target] = append(chains.byTarget[target], Hook{
		Target: target, Wrapper: wrapper, DeclaredIndex: m.nextID,
	})
	m.nextID++
}

func chainHasWrapper(chain []Hook, wrapper string) bool {
	for _, hook := range chain {
		if hook.Wrapper == wrapper {
			return true
		}
	}
	return false
}

func duplicateHookError(target, wrapper string) error {
	return fmt.Errorf("Hook %s -> %s already declared. Order matters. Please remove duplicate.", target, wrapper)
}

func (m *Model) addProtected(function string) {
	if _, present := m.protected[function]; present {
		return
	}
	m.protected[function] = struct{}{}
	m.protectedOrder = append(m.protectedOrder, function)
}

func (m *Model) addResolveHook(entry ResolveHook) {
	if _, present := m.resolve[entry.Function]; !present {
		m.resolveOrder = append(m.resolveOrder, entry.Function)
	}
	m.resolve[entry.Function] = entry
}

func (m *Model) filterResolveHooks(allowed map[string]struct{}) {
	kept := m.resolveOrder[:0]
	for _, function := range m.resolveOrder {
		entry, present := m.resolve[function]
		if !present {
			continue
		}
		if _, include := allowed[entry.Target]; include {
			kept = append(kept, function)
			continue
		}
		delete(m.resolve, function)
	}
	m.resolveOrder = kept
}

func (m *Model) addIntrinsic(symbol string, content []byte) {
	if _, present := m.intrinsics[symbol]; !present {
		m.intrinsicOrder = append(m.intrinsicOrder, symbol)
	}
	m.intrinsics[symbol] = append([]byte(nil), content...)
}

func (m *Model) isCatchHandler(function string) bool {
	for _, handler := range m.catches {
		if handler == function {
			return true
		}
	}
	return false
}

func (s *selections) add(target string, values []string) {
	if _, present := s.values[target]; !present {
		s.values[target] = make(map[string]struct{})
		s.order = append(s.order, target)
	}
	for _, value := range values {
		if _, present := s.values[target][value]; present {
			continue
		}
		s.values[target][value] = struct{}{}
		s.lists[target] = append(s.lists[target], value)
	}
}

func (s selections) contains(target, value string) bool {
	_, present := s.values[target][value]
	return present
}

func (m *Model) clone() *Model {
	result := &Model{
		machine:        m.machine,
		nextID:         m.nextID,
		external:       cloneHookChains(m.external),
		local:          cloneHookChains(m.local),
		preserve:       cloneSelections(m.preserve),
		optout:         cloneSelections(m.optout),
		protected:      make(map[string]struct{}, len(m.protected)),
		protectedOrder: append([]string(nil), m.protectedOrder...),
		resolve:        make(map[string]ResolveHook, len(m.resolve)),
		resolveOrder:   append([]string(nil), m.resolveOrder...),
		intrinsics:     make(map[string][]byte, len(m.intrinsics)),
		intrinsicOrder: append([]string(nil), m.intrinsicOrder...),
		catches:        make(map[string]string, len(m.catches)),
		catchOrder:     append([]string(nil), m.catchOrder...),
	}
	for value := range m.protected {
		result.protected[value] = struct{}{}
	}
	for key, value := range m.resolve {
		result.resolve[key] = value
	}
	for key, value := range m.intrinsics {
		result.intrinsics[key] = append([]byte(nil), value...)
	}
	for key, value := range m.catches {
		result.catches[key] = value
	}
	return result
}

func cloneHookChains(source hookChains) hookChains {
	result := hookChains{
		byTarget: make(map[string][]Hook, len(source.byTarget)),
		order:    append([]string(nil), source.order...),
	}
	for target, chain := range source.byTarget {
		result.byTarget[target] = append([]Hook(nil), chain...)
	}
	return result
}

func cloneSelections(source selections) selections {
	result := newSelections()
	result.order = append([]string(nil), source.order...)
	for target, values := range source.values {
		result.values[target] = make(map[string]struct{}, len(values))
		for value := range values {
			result.values[target][value] = struct{}{}
		}
	}
	for target, values := range source.lists {
		result.lists[target] = append([]string(nil), values...)
	}
	return result
}
