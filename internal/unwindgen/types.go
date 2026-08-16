// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package unwindgen

import (
	"context"
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var (
	ErrInvalidInput      = errors.New("unwindgen: invalid input")
	ErrUnsupportedDetail = errors.New("unwindgen: instruction detail is insufficient for safe unwind generation")
	ErrDynamicFrame      = errors.New("unwindgen: dynamic stack frame requires a frame pointer")
	ErrInvariant         = errors.New("unwindgen: COFF model invariant violation")
)

// DisassemblerFactory opens one x64 decoder. Build results are owned and
// closed by Generate; directly supplied disassemblers remain caller-owned.
type DisassemblerFactory func(context.Context, x86.Mode) (x86.Disassembler, error)

// Options controls portable instruction decoding.
type Options struct {
	Disassembler x86.Disassembler
	Factory      DisassemblerFactory
}

// UnsupportedError identifies the exact instruction or prologue property
// that cannot be proven without richer architecture detail.
type UnsupportedError struct {
	Function    string
	Offset      uint32
	Instruction string
	Reason      string
}

func (e *UnsupportedError) Error() string {
	if e == nil {
		return ErrUnsupportedDetail.Error()
	}
	detail := e.Reason
	if detail == "" {
		detail = "unsupported instruction semantics"
	}
	location := e.Function
	if location == "" {
		location = "<unknown>"
	}
	message := fmt.Sprintf("unwindgen: cannot prove +unwind for %s at .text+%#x: %s", location, e.Offset, detail)
	if e.Instruction != "" {
		message += " (" + e.Instruction + ")"
	}
	return message
}

func (e *UnsupportedError) Unwrap() error { return ErrUnsupportedDetail }

// DynamicFrameError retains Crystal Palace's exact user-facing remediation.
type DynamicFrameError struct {
	Function string
}

func (e *DynamicFrameError) Error() string {
	function := ""
	if e != nil {
		function = e.Function
	}
	return "I can't generate +unwind for " + function + ". Stack frame is dynamic. I need a frame pointer. Recompile module with -fno-omit-frame-pointer or decorate function with __attribute__((optimize(\"no-omit-frame-pointer\")))"
}

func (e *DynamicFrameError) Unwrap() error { return ErrDynamicFrame }

// Error wraps validation, disassembly, model, and transactional apply errors.
type Error struct {
	Stage     string
	Function  string
	Offset    uint32
	HasOffset bool
	Err       error
}

func (e *Error) Error() string {
	if e == nil {
		return ErrInvalidInput.Error()
	}
	stage := e.Stage
	if stage == "" {
		stage = "generation"
	}
	location := ""
	if e.Function != "" {
		location += " in " + e.Function
	}
	if e.HasOffset {
		location += fmt.Sprintf(" at .text+%#x", e.Offset)
	}
	cause := e.Err
	if cause == nil {
		cause = ErrInvalidInput
	}
	return fmt.Sprintf("unwindgen: %s%s: %v", stage, location, cause)
}

func (e *Error) Unwrap() []error {
	if e == nil || e.Err == nil || errors.Is(e.Err, ErrInvalidInput) {
		return []error{ErrInvalidInput}
	}
	return []error{ErrInvalidInput, e.Err}
}

// Function describes one generated RUNTIME_FUNCTION row. Leaf functions are
// listed separately in Result.SkippedLeaves.
type Function struct {
	Name         string
	BeginAddress uint32
	EndAddress   uint32
	UnwindOffset uint32
	Handler      string
}

// Result owns generated section data and deterministic reporting slices.
type Result struct {
	PDATA         *coff.Section
	XDATA         *coff.Section
	Functions     []Function
	SkippedLeaves []string
}

// Clone makes a deep defensive copy suitable for independent resource builds.
func (r Result) Clone() Result {
	return Result{
		PDATA:         cloneSection(r.PDATA),
		XDATA:         cloneSection(r.XDATA),
		Functions:     append([]Function(nil), r.Functions...),
		SkippedLeaves: append([]string(nil), r.SkippedLeaves...),
	}
}
