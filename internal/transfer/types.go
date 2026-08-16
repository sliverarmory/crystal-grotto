// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package transfer

import (
	"context"
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var (
	ErrInvalidInput      = errors.New("transfer: invalid input")
	ErrMalformedObject   = errors.New("transfer: malformed COFF object")
	ErrUnsupportedCall   = errors.New("transfer: unsupported __transfer call")
	ErrUnprovenPrologue  = errors.New("transfer: function prologue cannot be proven")
	ErrUnsupportedFlow   = errors.New("transfer: unsupported position-dependent instruction")
	ErrBranchRange       = errors.New("transfer: branch displacement is out of range")
	ErrUnsupportedUnwind = errors.New("transfer: unsupported existing unwind metadata")
)

// DisassemblerFactory opens one x64 decoder. Apply owns and closes the
// returned decoder. A decoder supplied directly in Options remains caller-owned.
type DisassemblerFactory func(context.Context, x86.Mode) (x86.Disassembler, error)

// Options controls decoder injection for one transfer expansion pass.
type Options struct {
	Disassembler x86.Disassembler
	Factory      DisassemblerFactory
}

// FunctionReport describes expansions in one function.
type FunctionReport struct {
	Name        string
	Calls       int
	Epilogue    []byte
	CallOffsets []uint32
}

// Report describes one successful Apply operation.
type Report struct {
	RewrittenCalls  int
	ConsumedNOPs    int
	RelaxedBranches int
	BytesBefore     int
	BytesAfter      int
	Functions       []FunctionReport
}

// Clone returns a defensive report copy.
func (r Report) Clone() Report {
	result := r
	result.Functions = make([]FunctionReport, len(r.Functions))
	for index, function := range r.Functions {
		result.Functions[index] = FunctionReport{
			Name:        function.Name,
			Calls:       function.Calls,
			Epilogue:    append([]byte(nil), function.Epilogue...),
			CallOffsets: append([]uint32(nil), function.CallOffsets...),
		}
	}
	return result
}

// CallError identifies a relocation or instruction that does not satisfy the
// canonical x64 CALL rel32 __transfer contract.
type CallError struct {
	Function string
	Offset   uint32
	Bytes    []byte
	Reason   string
}

func (e *CallError) Error() string {
	if e == nil {
		return ErrUnsupportedCall.Error()
	}
	return fmt.Sprintf("transfer: function %q call %#x (%x): %s", e.Function, e.Offset, e.Bytes, e.Reason)
}

func (e *CallError) Unwrap() error { return ErrUnsupportedCall }

// PrologueError identifies a prologue or later stack mutation that cannot be
// reversed with TransferCall's upstream PUSH/SUB RSP model.
type PrologueError struct {
	Function string
	Offset   uint32
	Bytes    []byte
	Reason   string
}

func (e *PrologueError) Error() string {
	if e == nil {
		return ErrUnprovenPrologue.Error()
	}
	return fmt.Sprintf("transfer: function %q prologue instruction %#x (%x): %s", e.Function, e.Offset, e.Bytes, e.Reason)
}

func (e *PrologueError) Unwrap() error { return ErrUnprovenPrologue }

// FlowError identifies position-dependent instruction semantics that cannot
// be repaired without Iced's architecture detail.
type FlowError struct {
	Function string
	Offset   uint32
	Bytes    []byte
	Reason   string
}

func (e *FlowError) Error() string {
	if e == nil {
		return ErrUnsupportedFlow.Error()
	}
	return fmt.Sprintf("transfer: function %q instruction %#x (%x): %s", e.Function, e.Offset, e.Bytes, e.Reason)
}

func (e *FlowError) Unwrap() error { return ErrUnsupportedFlow }

// BranchRangeError identifies a short-only LOOP/JCXZ-family branch that no
// longer reaches its target after transfer expansion.
type BranchRangeError struct {
	Function string
	Offset   uint32
	Target   uint32
}

func (e *BranchRangeError) Error() string {
	if e == nil {
		return ErrBranchRange.Error()
	}
	return fmt.Sprintf("transfer: function %q short-only branch %#x cannot reach %#x", e.Function, e.Offset, e.Target)
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
	return fmt.Sprintf("transfer: unwind section %q at %#x: %s", e.Section, e.Offset, e.Reason)
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
	return fmt.Sprintf("transfer: %s: %v", e.stage, e.err)
}

func (e *stageError) Unwrap() error { return e.err }

func malformed(stage string, err error) error {
	return &stageError{stage: stage, err: errors.Join(ErrMalformedObject, err)}
}

func invalid(stage string, err error) error {
	return &stageError{stage: stage, err: errors.Join(ErrInvalidInput, err)}
}
