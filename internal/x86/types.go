// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.
// See LICENSE.upstream.

package x86

import (
	"context"
	"errors"
	"fmt"
)

// Mode is the x86 execution mode used while decoding instructions.
type Mode uint8

const (
	Mode32 Mode = 32
	Mode64 Mode = 64
)

func (m Mode) String() string {
	switch m {
	case Mode32:
		return "x86"
	case Mode64:
		return "x64"
	default:
		return fmt.Sprintf("unknown-%d", uint8(m))
	}
}

var (
	// ErrClosed indicates that the disassembler has already released its
	// engine and cannot accept more work.
	ErrClosed = errors.New("x86: disassembler is closed")

	// ErrInvalidMode indicates a mode other than Mode32 or Mode64.
	ErrInvalidMode = errors.New("x86: invalid disassembly mode")

	// ErrInvalidInstruction identifies input that Capstone cannot consume as
	// a complete instruction stream. It covers both invalid encodings and a
	// final truncated instruction because Capstone does not distinguish them.
	ErrInvalidInstruction = errors.New("x86: invalid or truncated instruction")

	// ErrAddressOverflow indicates that an input stream would extend beyond
	// the uint64 address space.
	ErrAddressOverflow = errors.New("x86: instruction address overflows uint64")

	// ErrInputTooLarge indicates that input cannot be represented by the
	// WebAssembly binding's uint32-sized allocation interface.
	ErrInputTooLarge = errors.New("x86: input exceeds Capstone allocation limit")

	// ErrNilContext indicates that a nil context was supplied. The underlying
	// Wazero runtime requires a non-nil context.
	ErrNilContext = errors.New("x86: nil context")

	// ErrBackendInvariant indicates malformed or internally inconsistent data
	// returned by the disassembly backend.
	ErrBackendInvariant = errors.New("x86: Capstone returned inconsistent instruction data")
)

// Detail contains the generic instruction metadata exposed by go-capstone.
// It is not Capstone's architecture-specific cs_detail structure and is not a
// substitute for the Iced semantic data described in the package documentation.
type Detail struct {
	InstructionID   uint32
	AliasID         uint64
	IsAlias         bool
	UsesAliasDetail bool
}

// Instruction is a deterministic, backend-independent decoded instruction.
// Bytes owns its storage. Form is empty when the backend cannot provide a
// canonical operand-kind form; consumers must not derive one from Operands.
type Instruction struct {
	Address  uint64
	Bytes    []byte
	Mnemonic string
	Operands string
	Form     string
	Detail   *Detail
}

// Assembly returns the formatted mnemonic and operands without address or raw
// byte columns.
func (i Instruction) Assembly() string {
	if i.Operands == "" {
		return i.Mnemonic
	}
	return i.Mnemonic + " " + i.Operands
}

// Disassembler decodes complete x86 instruction streams and owns resources
// that must be released with Close. Implementations must be safe for concurrent
// calls. A successful Disassemble consumes every input byte.
type Disassembler interface {
	Disassemble(ctx context.Context, code []byte, address uint64) ([]Instruction, error)
	Close(ctx context.Context) error
}

// DecodeError reports the first byte that could not be decoded or failed a
// backend invariant. No partial instruction slice is returned with this error.
type DecodeError struct {
	Offset    int
	Address   uint64
	Remaining []byte
	Err       error
}

func (e *DecodeError) Error() string {
	err := e.Err
	if err == nil {
		err = ErrInvalidInstruction
	}
	return fmt.Sprintf("%v at byte offset %#x (address %#x, %d bytes remain)", err, e.Offset, e.Address, len(e.Remaining))
}

func (e *DecodeError) Unwrap() error {
	if e.Err == nil {
		return ErrInvalidInstruction
	}
	return e.Err
}
