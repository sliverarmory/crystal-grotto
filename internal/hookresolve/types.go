// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package hookresolve

import (
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidInput    = errors.New("hookresolve: invalid input")
	ErrUnsupportedForm = errors.New("hookresolve: unsupported intrinsic form")
	ErrInvalidModel    = errors.New("hookresolve: invalid COFF model")
)

// Options controls the randomized addhook order. Seed reproduces
// java.util.Random and Collections.shuffle; Random consumes unsigned 31-bit
// values as four-byte big-endian words. They are mutually exclusive.
type Options struct {
	Random io.Reader
	Seed   *int64
}

// Report describes generated intrinsic sites and table entries.
type Report struct {
	RewrittenSites  int
	ResolverEntries int
	RandomDraws     int
	StubSection     string
}

// SiteError preserves the exact source location of a rejected intrinsic.
type SiteError struct {
	Section string
	Offset  uint32
	Symbol  string
	Err     error
}

func (e *SiteError) Error() string {
	return fmt.Sprintf("hookresolve: section %s at %#x symbol %q: %v", e.Section, e.Offset, e.Symbol, e.Err)
}

func (e *SiteError) Unwrap() error { return e.Err }
