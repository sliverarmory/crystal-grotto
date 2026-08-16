// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package resolver

import (
	"errors"

	"github.com/sliverarmory/crystal-grotto/internal/binutil"
)

var defaultAPIs = []string{"LoadLibraryA", "GetProcAddress"}

// DefaultAPITable returns the two bootstrap APIs installed by ExportObject.
func DefaultAPITable() []string { return append([]string(nil), defaultAPIs...) }

// ParseAPITable parses and validates the string supplied to the spec import
// command. Empty interior entries and additional APIs retain declaration order.
func ParseAPITable(value string) ([]string, error) {
	return ValidateAPITable(binutil.SplitList(value))
}

// ValidateAPITable validates the PICO internal-API contract and returns a
// defensive copy suitable for storage in an artifact configuration.
func ValidateAPITable(apis []string) ([]string, error) {
	if len(apis) < 1 || apis[0] != "LoadLibraryA" {
		return nil, errors.New("LoadLibraryA is required as the first API entry.")
	}
	if len(apis) < 2 || apis[1] != "GetProcAddress" {
		return nil, errors.New("GetProcAddress is required as the second API entry.")
	}
	return append([]string(nil), apis...), nil
}
