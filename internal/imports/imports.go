// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

// Package imports extracts the Win32 APIs referenced by COFF relocations or a
// PE import address table.
package imports

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/pe"
)

type Import struct {
	Module    string
	Function  string
	Ordinal   uint16
	ByOrdinal bool
}

func (i Import) String() string {
	module := strings.ToUpper(i.Module)
	if i.ByOrdinal {
		return fmt.Sprintf("%s$(#%d)", module, i.Ordinal)
	}
	return module + "$" + i.Function
}

func (i Import) Target() string { return i.Module + "$" + i.Function }

type Result struct {
	Imports []Import
}

// Strings returns sorted, unique MODULE$Function representations.
func (r *Result) Strings() []string {
	unique := make(map[string]struct{}, len(r.Imports))
	for _, imported := range r.Imports {
		unique[imported.String()] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// Parse auto-detects a PE image or supported COFF object.
func Parse(contents []byte) (*Result, error) {
	if len(contents) < 2 {
		return nil, errors.New("imports: input is too short")
	}
	magic := binary.LittleEndian.Uint16(contents[:2])
	if magic == 0x5a4d {
		object, err := pe.Parse(contents)
		if err != nil {
			return nil, err
		}
		return FromPE(object), nil
	}
	machine := coff.Machine(magic)
	if machine == coff.MachineI386 || machine == coff.MachineAMD64 || machine == coff.MachineARM64 {
		object, err := coff.Parse(contents)
		if err != nil {
			return nil, err
		}
		return FromCOFF(object), nil
	}
	return nil, errors.New("imports: argument is not a COFF object or PE image")
}

func FromCOFF(object *coff.Object) *Result {
	result := &Result{}
	if object == nil {
		return result
	}
	for _, section := range object.Sections {
		for _, relocation := range section.Relocations {
			if imported, ok := ParseSymbol(relocation.SymbolName); ok {
				result.Imports = append(result.Imports, imported)
			}
		}
	}
	return result
}

func FromPE(object *pe.Object) *Result {
	result := &Result{}
	if object == nil {
		return result
	}
	for _, entry := range object.Imports {
		module := entry.Module
		if len(module) >= 4 && strings.EqualFold(module[len(module)-4:], ".dll") {
			module = module[:len(module)-4]
		}
		result.Imports = append(result.Imports, Import{
			Module:    module,
			Function:  entry.Function,
			Ordinal:   entry.Ordinal,
			ByOrdinal: entry.ByOrdinal,
		})
	}
	return result
}

// ParseSymbol decodes Crystal Palace's __imp_[MODULE$]Function convention.
func ParseSymbol(symbol string) (Import, bool) {
	var work string
	switch {
	case strings.HasPrefix(symbol, "__imp__"):
		work = strings.TrimPrefix(symbol, "__imp__")
	case strings.HasPrefix(symbol, "__imp_"):
		work = strings.TrimPrefix(symbol, "__imp_")
	default:
		return Import{}, false
	}
	result := Import{}
	parts := javaSplit(work, "$")
	if len(parts) == 2 {
		result.Module = parts[0]
		result.Function = parts[1]
	} else {
		result.Function = work
	}
	decorated := javaSplit(result.Function, "@")
	if len(decorated) == 2 {
		result.Function = decorated[0]
	}
	return result, true
}

// javaSplit reproduces Java String.split's omission of trailing empty fields.
func javaSplit(value, separator string) []string {
	parts := strings.Split(value, separator)
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}
