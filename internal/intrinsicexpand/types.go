// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package intrinsicexpand

import (
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/ised"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var (
	ErrInvalidInput    = errors.New("intrinsicexpand: invalid input")
	ErrUnsupportedForm = errors.New("intrinsicexpand: unsupported intrinsic form")
	ErrInvalidModel    = errors.New("intrinsicexpand: invalid COFF model")
)

// Options controls decoder ownership while lifting the source object.
// Disassembler is caller-owned; a decoder returned by NewDisassembler is
// package-owned. The fields are mutually exclusive.
type Options struct {
	Disassembler    x86.Disassembler
	NewDisassembler ised.DisassemblerFactory
}

// Site records one consumed user-intrinsic call.
type Site struct {
	Function    string
	Symbol      string
	Offset      uint32
	OriginalLen int
	ResultLen   int
}

// Report describes all user-intrinsic expansions. Sites owns its storage.
type Report struct {
	// Sites and BytesDelta describe configured user-byte sites only. Named
	// hash/tag built-ins share the rebuild for upstream pass-order parity but
	// are intentionally not reported as user intrinsics.
	Sites      []Site
	BytesDelta int64
}

// SiteError preserves the exact rejected source location.
type SiteError struct {
	Function string
	Symbol   string
	Offset   uint32
	Err      error
}

func (e *SiteError) Error() string {
	return fmt.Sprintf("intrinsicexpand: function %q at %#x symbol %q: %v", e.Function, e.Offset, e.Symbol, e.Err)
}

func (e *SiteError) Unwrap() error { return e.Err }
