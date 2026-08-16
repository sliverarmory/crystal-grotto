// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package hooks

import (
	"fmt"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

// CheckFunction implements ExportObject.check, including x86 decoration
// suggestions and exact function-type validation.
func CheckFunction(object *coff.Object, symbol string) error {
	if object == nil {
		return ErrNilObject
	}
	found := object.GetSymbol(symbol)
	if found == nil && object.Machine == coff.MachineI386 {
		stdcall := symbol + "@"
		underscoredStdcall := "_" + symbol + "@"
		for _, candidate := range object.Symbols {
			if candidate == nil {
				continue
			}
			if strings.HasPrefix(candidate.Name, stdcall) || strings.HasPrefix(candidate.Name, underscoredStdcall) {
				return fmt.Errorf("Symbol %s does not exist. Did you mean %s?", symbol, candidate.Name)
			}
		}
		if candidate := object.GetSymbol("_" + symbol); candidate != nil {
			return fmt.Errorf("Symbol %s does not exist. Did you mean _%s?", symbol, symbol)
		}
	}
	if found == nil {
		return fmt.Errorf("Symbol %s does not exist.", symbol)
	}
	if !found.IsFunction() {
		return fmt.Errorf("Symbol %s is not a function.", symbol)
	}
	return nil
}
