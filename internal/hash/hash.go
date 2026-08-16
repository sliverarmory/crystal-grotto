// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package hash

import (
	"fmt"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/binutil"
)

// Algorithm is a named Crystal Palace-compatible 32-bit hash.
type Algorithm interface {
	Name() string
	Sum32(data []byte) uint32
}

var algorithms = []Algorithm{
	DJB2{},
	FNV1A{},
	ROR13{},
	SDBM{},
}

var byName = func() map[string]Algorithm {
	result := make(map[string]Algorithm, len(algorithms))
	for _, algorithm := range algorithms {
		result[algorithm.Name()] = algorithm
	}
	return result
}()

// Names returns algorithm names in the stable upstream registry order.
func Names() []string {
	result := make([]string, len(algorithms))
	for i, algorithm := range algorithms {
		result[i] = algorithm.Name()
	}
	return result
}

// NamesString returns the exact comma-separated registry description used in
// upstream diagnostics.
func NamesString() string { return strings.Join(Names(), ", ") }

// IsName reports whether name exactly identifies an algorithm. Names are
// deliberately lower-case and case-sensitive.
func IsName(name string) bool {
	_, ok := byName[name]
	return ok
}

// Get looks up an algorithm by its case-sensitive name.
func Get(name string) (Algorithm, error) {
	algorithm, ok := byName[name]
	if !ok {
		return nil, fmt.Errorf("unknown hash algorithm %q", name)
	}
	return algorithm, nil
}

// Apply hashes data with a named algorithm.
func Apply(name string, data []byte) (uint32, error) {
	algorithm, err := Get(name)
	if err != nil {
		return 0, err
	}
	return algorithm.Sum32(data), nil
}

// Prefix returns the recognized two- or three-underscore linker-intrinsic
// prefix at the start of symbol.
func Prefix(symbol string) (string, bool) {
	for _, algorithm := range algorithms {
		for _, underscores := range []string{"__", "___"} {
			prefix := underscores + algorithm.Name() + "_"
			if strings.HasPrefix(symbol, prefix) {
				return prefix, true
			}
		}
	}
	return "", false
}

// MatchesPrefix reports whether symbol starts with a registered intrinsic
// prefix.
func MatchesPrefix(symbol string) bool {
	_, ok := Prefix(symbol)
	return ok
}

// GetFromPrefix returns the algorithm selected by symbol's intrinsic prefix.
func GetFromPrefix(symbol string) (Algorithm, error) {
	for _, algorithm := range algorithms {
		if strings.HasPrefix(symbol, "__"+algorithm.Name()+"_") ||
			strings.HasPrefix(symbol, "___"+algorithm.Name()+"_") {
			return algorithm, nil
		}
	}
	return nil, fmt.Errorf("symbol %q has no registered hash prefix", symbol)
}

// RemovePrefix removes a registered intrinsic prefix without risking the
// substring panic present in the Java implementation.
func RemovePrefix(symbol string) (string, error) {
	prefix, ok := Prefix(symbol)
	if !ok {
		return "", fmt.Errorf("symbol %q has no registered hash prefix", symbol)
	}
	return strings.TrimPrefix(symbol, prefix), nil
}

// ApplyIntrinsic hashes the portion of symbol after its registered prefix.
func ApplyIntrinsic(symbol string) (uint32, error) {
	algorithm, err := GetFromPrefix(symbol)
	if err != nil {
		return 0, err
	}
	value, err := RemovePrefix(symbol)
	if err != nil {
		return 0, err
	}
	return algorithm.Sum32([]byte(value)), nil
}

// ApplyModule applies the DFR module casing/encoding contract: the module is
// upper-cased, ".DLL" is appended, and the result is hashed as UTF-16LE.
func ApplyModule(name, module string) (uint32, error) {
	return Apply(name, binutil.UTF16LE(strings.ToUpper(module)+".DLL"))
}

// ApplyFunction hashes a function name exactly as supplied. Function names are
// case-sensitive and are not normalized upstream.
func ApplyFunction(name, function string) (uint32, error) {
	return Apply(name, []byte(function))
}
