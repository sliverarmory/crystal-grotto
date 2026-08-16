// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package blockparty

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var (
	ErrInvalidInput        = errors.New("blockparty: invalid input")
	ErrMalformedObject     = errors.New("blockparty: malformed COFF object")
	ErrUnsupportedSemantic = errors.New("blockparty: unsupported instruction semantics")
	ErrBranchRange         = errors.New("blockparty: branch displacement is out of range")
	ErrUnsupportedUnwind   = errors.New("blockparty: unsupported existing unwind metadata")
)

// DisassemblerFactory opens one architecture-specific decoder. Apply owns and
// closes returned decoders. A decoder supplied directly in Options remains
// caller-owned.
type DisassemblerFactory func(context.Context, x86.Mode) (x86.Disassembler, error)

// Options controls one +blockparty pass. Seed selects a java.util.Random-
// compatible stream. Random supplies unsigned 31-bit values as four-byte
// big-endian words to Java's bounded-selection algorithm. The two fields are
// mutually exclusive; with neither set crypto/rand.Reader is used.
type Options struct {
	Random io.Reader
	Seed   *int64

	Disassembler x86.Disassembler
	Factory      DisassemblerFactory
}

// FunctionReport records the original block leaders in the selected order.
// The first element is always the original first block.
type FunctionReport struct {
	Name          string
	OriginalOrder []uint32
	SelectedOrder []uint32
}

// Report describes the observable work performed by Apply.
type Report struct {
	EligibleFunctions int
	ShuffledFunctions int
	Blocks            int
	RandomDraws       int
	InsertedJumps     int
	RemovedJumps      int
	RelaxedBranches   int
	Functions         []FunctionReport
}

// Clone returns a defensive report copy.
func (r Report) Clone() Report {
	result := r
	result.Functions = make([]FunctionReport, len(r.Functions))
	for index, function := range r.Functions {
		result.Functions[index] = FunctionReport{
			Name:          function.Name,
			OriginalOrder: append([]uint32(nil), function.OriginalOrder...),
			SelectedOrder: append([]uint32(nil), function.SelectedOrder...),
		}
	}
	return result
}

// UnsupportedError identifies an instruction whose Iced-level semantics
// cannot be established from portable Capstone output and its raw encoding.
type UnsupportedError struct {
	Function string
	Offset   uint32
	Bytes    []byte
	Reason   string
}

func (e *UnsupportedError) Error() string {
	if e == nil {
		return ErrUnsupportedSemantic.Error()
	}
	return fmt.Sprintf("blockparty: function %q instruction %#x (%x): %s", e.Function, e.Offset, e.Bytes, e.Reason)
}

func (e *UnsupportedError) Unwrap() error { return ErrUnsupportedSemantic }

// BranchRangeError identifies a short-only LOOP/JCXZ-family branch that no
// longer reaches its target after block permutation.
type BranchRangeError struct {
	Function string
	Offset   uint32
	Target   uint32
}

func (e *BranchRangeError) Error() string {
	if e == nil {
		return ErrBranchRange.Error()
	}
	return fmt.Sprintf("blockparty: function %q short-only branch %#x cannot reach %#x", e.Function, e.Offset, e.Target)
}

func (e *BranchRangeError) Unwrap() error { return ErrBranchRange }

// UnwindError reports existing pdata that cannot be proven safe to retain.
type UnwindError struct {
	Section string
	Offset  uint32
	Reason  string
}

func (e *UnwindError) Error() string {
	if e == nil {
		return ErrUnsupportedUnwind.Error()
	}
	return fmt.Sprintf("blockparty: unwind section %q at %#x: %s", e.Section, e.Offset, e.Reason)
}

func (e *UnwindError) Unwrap() error { return ErrUnsupportedUnwind }

type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string {
	if e == nil {
		return ErrInvalidInput.Error()
	}
	return fmt.Sprintf("blockparty: %s: %v", e.stage, e.err)
}

func (e *stageError) Unwrap() error { return e.err }

func malformed(stage string, err error) error {
	return &stageError{stage: stage, err: errors.Join(ErrMalformedObject, err)}
}

func invalid(stage string, err error) error {
	return &stageError{stage: stage, err: errors.Join(ErrInvalidInput, err)}
}
