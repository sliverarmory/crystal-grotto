// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package shatter

import (
	"errors"
	"fmt"
	"io"
)

// Options controls one +shatter pass. Seed selects a java.util.Random-
// compatible stream. Random supplies unsigned 31-bit values as four-byte
// big-endian words to the same bounded-selection algorithm. The fields are
// mutually exclusive; when both are nil crypto/rand.Reader is used.
type Options struct {
	Random io.Reader
	Seed   *int64
}

// BlockAssignment records where one original non-prologue block was placed.
// Start is the block's original .text offset.
type BlockAssignment struct {
	SourceFunction string
	HomeFunction   string
	Start          uint32
}

// FunctionLayout describes the physical region beginning at a function
// symbol after shattering. Logical blocks from other functions may be present.
type FunctionLayout struct {
	Name   string
	Blocks []BlockAssignment
}

// Report describes observable work performed by Apply.
type Report struct {
	Functions        int
	OriginalBlocks   int
	ShuffledBlocks   int
	RandomDraws      int
	Connectors       int
	HealedJumps      int
	ExpandedBranches int
	Assignments      []BlockAssignment
	Layouts          []FunctionLayout
}

var (
	// ErrUnsupportedControlFlow marks an instruction whose exact Iced control-
	// flow behavior cannot be proven with go-capstone's available detail.
	ErrUnsupportedControlFlow = errors.New("shatter: unsupported control flow")
	// ErrUnsupportedMetadata marks metadata that would become stale when
	// logical blocks cross physical function boundaries.
	ErrUnsupportedMetadata = errors.New("shatter: unsupported metadata")
)

// UnsupportedControlFlowError reports the precise instruction at a semantic
// compatibility boundary. Bytes is an owned copy.
type UnsupportedControlFlowError struct {
	Function string
	Offset   uint32
	Bytes    []byte
	Reason   string
}

func (e *UnsupportedControlFlowError) Error() string {
	return fmt.Sprintf("shatter: function %q instruction %#x (%x): %s", e.Function, e.Offset, e.Bytes, e.Reason)
}

func (e *UnsupportedControlFlowError) Unwrap() error { return ErrUnsupportedControlFlow }

// UnsupportedMetadataError identifies metadata which cannot be repaired
// without Iced's full function and unwind semantics.
type UnsupportedMetadataError struct {
	Section string
	Reason  string
}

func (e *UnsupportedMetadataError) Error() string {
	if e.Section == "" {
		return fmt.Sprintf("shatter: unsupported metadata: %s", e.Reason)
	}
	return fmt.Sprintf("shatter: unsupported metadata in %q: %s", e.Section, e.Reason)
}

func (e *UnsupportedMetadataError) Unwrap() error { return ErrUnsupportedMetadata }
