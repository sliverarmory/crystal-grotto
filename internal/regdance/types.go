// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package regdance

import (
	"errors"
	"fmt"
	"io"
)

// Options controls one +regdance pass. Seed selects a java.util.Random-
// compatible stream. Random supplies independent unsigned 31-bit values as
// four-byte big-endian words to the same bounded-selection algorithm. The two
// fields are mutually exclusive; when both are nil crypto/rand.Reader is used.
type Options struct {
	Random io.Reader
	Seed   *int64
}

// Register is a normalized 64-bit general-purpose register. Crystal Palace
// normalizes 8-, 16-, and 32-bit uses to this register before choosing a
// permutation, including while processing x86 code.
type Register uint8

const (
	RBX Register = 3
	RBP Register = 5
	RSI Register = 6
	RDI Register = 7
	R12 Register = 12
	R13 Register = 13
	R14 Register = 14
	R15 Register = 15
)

func (r Register) String() string {
	switch r {
	case RBX:
		return "rbx"
	case RBP:
		return "rbp"
	case RSI:
		return "rsi"
	case RDI:
		return "rdi"
	case R12:
		return "r12"
	case R13:
		return "r13"
	case R14:
		return "r14"
	case R15:
		return "r15"
	default:
		return fmt.Sprintf("register-%d", uint8(r))
	}
}

// Mapping records one source-to-destination entry in the selected register
// permutation. Identity entries are retained because upstream retains them in
// its remap table and still consumes shuffle randomness.
type Mapping struct {
	From Register
	To   Register
}

// FunctionReport describes one function that passed upstream's saved-register
// and single-exit checks.
type FunctionReport struct {
	Name                string
	Mapping             []Mapping
	ChangedInstructions int
}

// Report describes the observable work performed by Apply.
type Report struct {
	EligibleFunctions   int
	RemappedFunctions   int
	ChangedInstructions int
	RandomDraws         int
	Functions           []FunctionReport
}

var (
	// ErrUnsupportedInstruction marks an otherwise eligible instruction whose
	// Iced operand/encoding semantics cannot be reproduced safely.
	ErrUnsupportedInstruction = errors.New("regdance: unsupported instruction")
	// ErrUnsupportedUnwind marks existing unwind metadata that would become
	// stale and cannot be repaired without guessing.
	ErrUnsupportedUnwind = errors.New("regdance: unsupported unwind metadata")
)

// UnsupportedInstructionError reports a precise, typed compatibility
// boundary. Bytes is an owned copy and can be retained by the caller.
type UnsupportedInstructionError struct {
	Function string
	Offset   uint32
	Bytes    []byte
	Reason   string
}

func (e *UnsupportedInstructionError) Error() string {
	return fmt.Sprintf("regdance: function %q instruction %#x (%x): %s", e.Function, e.Offset, e.Bytes, e.Reason)
}

func (e *UnsupportedInstructionError) Unwrap() error { return ErrUnsupportedInstruction }

// UnsupportedUnwindError identifies an existing unwind section that cannot
// remain valid after a proposed rewrite.
type UnsupportedUnwindError struct {
	Function string
	Offset   uint32
	Reason   string
}

func (e *UnsupportedUnwindError) Error() string {
	return fmt.Sprintf("regdance: function %q at %#x: %s", e.Function, e.Offset, e.Reason)
}

func (e *UnsupportedUnwindError) Unwrap() error { return ErrUnsupportedUnwind }
