// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package resolver

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/binutil"
	"github.com/sliverarmory/crystal-grotto/internal/coff"
	crystalhash "github.com/sliverarmory/crystal-grotto/internal/hash"
)

// Method is a DFR argument contract.
type Method string

const (
	MethodStrings Method = "strings"
	MethodROR13   Method = "ror13"
	MethodDJB2    Method = "djb2"
	MethodFNV1A   Method = "fnv1a"
	MethodSDBM    Method = "sdbm"
)

// ParseMethod validates the case-sensitive method names accepted by dfr.
func ParseMethod(value string) (Method, error) {
	method := Method(value)
	if method == MethodStrings || method.IsHash() {
		return method, nil
	}
	return "", fmt.Errorf("invalid DFR method %q; use strings, %s", value, crystalhash.NamesString())
}

// IsHash reports whether the resolver accepts DWORD module/function hashes.
func (m Method) IsHash() bool { return crystalhash.IsName(string(m)) }

// IsStrings reports whether the resolver accepts two string pointers.
func (m Method) IsStrings() bool { return m == MethodStrings }

// Resolver describes one validated resolver function and its contract.
type Resolver struct {
	Function string
	Method   Method
	modules  []string
}

// Modules returns a defensive, deterministic copy of the explicit module set.
func (r Resolver) Modules() []string { return append([]string(nil), r.modules...) }

// ValidFor reports whether an explicit resolver covers module. Module matching
// is case-insensitive through the same upper-case normalization as upstream.
func (r Resolver) ValidFor(module string) bool {
	module = strings.ToUpper(module)
	for _, candidate := range r.modules {
		if candidate == module {
			return true
		}
	}
	return false
}

// Hash applies this resolver's named hash contract.
func (r Resolver) Hash(value []byte) (uint32, error) {
	if !r.Method.IsHash() {
		return 0, fmt.Errorf("Resolver %s (%s) is not a hash resolver", r.Function, r.Method)
	}
	return crystalhash.Apply(string(r.Method), value)
}

func (r Resolver) String() string {
	if len(r.modules) == 0 {
		return fmt.Sprintf("Resolver %s (%s)", r.Function, r.Method)
	}
	return fmt.Sprintf("Resolver %s (%s) for [%s]", r.Function, r.Method, strings.Join(r.modules, ", "))
}

// Directive is one replayable dfr command. Default distinguishes the two-
// argument default form from a three-argument form with an empty module set.
type Directive struct {
	Function string
	Method   Method
	Modules  []string
	Default  bool
	Clear    bool
}

// ParseDirective translates resolved spec arguments and the +clear option.
func ParseDirective(arguments []string, clear bool) (Directive, error) {
	if len(arguments) != 2 && len(arguments) != 3 {
		return Directive{}, fmt.Errorf("dfr expects 2 or 3 arguments, got %d", len(arguments))
	}
	method, err := ParseMethod(arguments[1])
	if err != nil {
		return Directive{}, err
	}
	directive := Directive{Function: arguments[0], Method: method, Default: len(arguments) == 2, Clear: clear}
	if len(arguments) == 3 {
		for _, module := range binutil.SplitSet(strings.ToUpper(arguments[2])) {
			directive.Modules = append(directive.Modules, module)
		}
	}
	return directive, nil
}

// Configuration is an immutable resolver selection snapshot. Its unexported
// storage makes a value safe for concurrent reads and reuse across plans.
type Configuration struct {
	resolvers       []Resolver
	defaultResolver *Resolver
}

// EmptyConfiguration returns a configuration with no DFR behavior.
func EmptyConfiguration() Configuration { return Configuration{} }

// HasResolvers reports whether ResolveAPI would run upstream.
func (c Configuration) HasResolvers() bool { return len(c.resolvers) != 0 || c.defaultResolver != nil }

// Resolvers returns explicit module-scoped resolvers in declaration order.
func (c Configuration) Resolvers() []Resolver { return cloneResolvers(c.resolvers) }

// Default returns the default resolver, if configured.
func (c Configuration) Default() (Resolver, bool) {
	if c.defaultResolver == nil {
		return Resolver{}, false
	}
	return cloneResolver(*c.defaultResolver), true
}

// ResolverFunctions returns sorted unique resolver function names.
func (c Configuration) ResolverFunctions() []string {
	unique := make(map[string]struct{})
	for _, resolver := range c.allResolvers() {
		unique[resolver.Function] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for function := range unique {
		result = append(result, function)
	}
	sort.Strings(result)
	return result
}

// Resolve applies first-declared module-specific precedence and then the
// current default resolver.
func (c Configuration) Resolve(imported Import) (Resolver, error) {
	for _, resolver := range c.resolvers {
		if resolver.ValidFor(imported.Module) {
			return cloneResolver(resolver), nil
		}
	}
	if c.defaultResolver != nil {
		return cloneResolver(*c.defaultResolver), nil
	}
	return Resolver{}, fmt.Errorf("No DFR resolver matches %s", imported.Symbol)
}

// Replay validates and applies dfr directives transactionally. On error the
// supplied base configuration remains usable and no partial result is returned.
func Replay(object *coff.Object, base Configuration, directives []Directive) (Configuration, error) {
	if object == nil {
		return Configuration{}, errors.New("resolver: nil COFF object")
	}
	next := cloneConfiguration(base)
	for index, directive := range directives {
		if directive.Clear {
			next = Configuration{}
		}
		method, err := ParseMethod(string(directive.Method))
		if err != nil {
			return Configuration{}, fmt.Errorf("dfr directive %d: %w", index, err)
		}
		if directive.Default && len(directive.Modules) != 0 {
			return Configuration{}, fmt.Errorf("dfr directive %d: default resolver cannot specify modules", index)
		}
		if err := validateResolverFunction(object, directive.Function); err != nil {
			return Configuration{}, fmt.Errorf("dfr directive %d: %w", index, err)
		}
		for _, existing := range next.allResolvers() {
			if existing.Function == directive.Function && existing.Method != method {
				return Configuration{}, fmt.Errorf("%s uses a different contract for function %s", existing, existing.Function)
			}
		}

		resolver := Resolver{Function: directive.Function, Method: method}
		if !directive.Default {
			seen := make(map[string]struct{}, len(directive.Modules))
			for _, module := range directive.Modules {
				module = strings.ToUpper(strings.TrimSpace(module))
				if _, exists := seen[module]; exists {
					continue
				}
				seen[module] = struct{}{}
				resolver.modules = append(resolver.modules, module)
			}
			next.resolvers = append(next.resolvers, resolver)
			continue
		}
		next.defaultResolver = &resolver
	}
	return next, nil
}

func validateResolverFunction(object *coff.Object, function string) error {
	symbol := object.GetSymbol(function)
	if symbol == nil {
		return fmt.Errorf("Symbol %s does not exist.", function)
	}
	if !symbol.IsFunction() {
		return fmt.Errorf("Symbol %s is not a function.", function)
	}
	return nil
}

func (c Configuration) allResolvers() []Resolver {
	result := cloneResolvers(c.resolvers)
	if c.defaultResolver != nil {
		result = append(result, cloneResolver(*c.defaultResolver))
	}
	return result
}

func cloneConfiguration(value Configuration) Configuration {
	result := Configuration{resolvers: cloneResolvers(value.resolvers)}
	if value.defaultResolver != nil {
		resolver := cloneResolver(*value.defaultResolver)
		result.defaultResolver = &resolver
	}
	return result
}

func cloneResolvers(values []Resolver) []Resolver {
	result := make([]Resolver, len(values))
	for index, value := range values {
		result[index] = cloneResolver(value)
	}
	return result
}

func cloneResolver(value Resolver) Resolver {
	value.modules = append([]string(nil), value.modules...)
	return value
}
