// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package resolver

import (
	"fmt"
	"strings"

	crystalhash "github.com/sliverarmory/crystal-grotto/internal/hash"
	coffimports "github.com/sliverarmory/crystal-grotto/internal/imports"
)

// Import is the parsed form of an upstream __imp_[MODULE$]Function symbol.
type Import struct {
	Symbol   string
	Module   string
	Function string
	Valid    bool
}

// ParseImport parses both the x64 __imp_ and x86 __imp__ spellings. Crystal
// Palace accepts either prefix independently of the object architecture.
func ParseImport(symbol string) (Import, bool) {
	parsed, ok := coffimports.ParseSymbol(symbol)
	if !ok {
		return Import{Symbol: symbol}, false
	}
	return Import{Symbol: symbol, Module: parsed.Module, Function: parsed.Function, Valid: true}, true
}

// WithRequiredModule supplies KERNEL32 for the two naked bootstrap APIs and
// rejects every other import that is not in MODULE$Function form.
func (i Import) WithRequiredModule() (Import, error) {
	if i.Module != "" {
		return i, nil
	}
	if i.Function == "GetProcAddress" || i.Function == "LoadLibraryA" {
		i.Module = "KERNEL32"
		return i, nil
	}
	return Import{}, fmt.Errorf("Function %s is not in MODULE$Function format", i.Function)
}

// Target returns the upstream module/function representation. A naked import
// begins with '$', matching ParseImport.getTarget().
func (i Import) Target() string { return i.Module + "$" + i.Function }

// ModuleHash applies the resolver's hash to upper-case MODULE.DLL encoded as
// UTF-16LE, matching the Windows loader-list hashing contract.
func (i Import) ModuleHash(resolver Resolver) (uint32, error) {
	if !resolver.Method.IsHash() {
		return 0, fmt.Errorf("resolver method %q does not hash imports", resolver.Method)
	}
	return crystalhash.ApplyModule(string(resolver.Method), i.Module)
}

// FunctionHash hashes the case-sensitive function name as UTF-8 bytes.
func (i Import) FunctionHash(resolver Resolver) (uint32, error) {
	if !resolver.Method.IsHash() {
		return 0, fmt.Errorf("resolver method %q does not hash imports", resolver.Method)
	}
	return crystalhash.ApplyFunction(string(resolver.Method), i.Function)
}

func (i Import) String() string {
	if i.Symbol == "" {
		return i.Target()
	}
	if !i.Valid {
		return i.Symbol + " (not an import)"
	}
	return strings.Join([]string{i.Symbol, i.Module, i.Function}, ", ")
}
