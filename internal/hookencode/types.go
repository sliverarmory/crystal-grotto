// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package hookencode

import (
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

var (
	ErrNilContext         = errors.New("hookencode: nil context")
	ErrNilObject          = errors.New("hookencode: nil COFF object")
	ErrNilModel           = errors.New("hookencode: nil hook model")
	ErrUnsupportedMachine = errors.New("hookencode: unsupported machine")
	ErrUnsupportedForm    = errors.New("hookencode: unsupported instruction or addressing form")
	ErrRebuildRequired    = errors.New("hookencode: length-changing rebuild required")
	ErrInvalidPlan        = errors.New("hookencode: invalid rewrite plan")
	ErrBranchRange        = errors.New("hookencode: replacement branch is out of range")
	ErrResolveHook        = errors.New("hookencode: __resolve_hook expansion is not implemented")
)

// Pass is one upstream Modify pass, in application order.
type Pass string

const (
	PassIntrinsic Pass = "intrinsic"
	PassRedirect  Pass = "redirect"
	PassAttach    Pass = "attach"
)

// Form is one source instruction shape accepted by the built-in encoder.
type Form string

const (
	FormCallRel32       Form = "CALL rel32"
	FormJumpRel32       Form = "JMP rel32"
	FormJumpRel8        Form = "JMP rel8"
	FormCallIndirect64  Form = "CALL r/m64"
	FormJumpIndirect64  Form = "JMP r/m64"
	FormMoveIndirect64  Form = "MOV r64, r/m64"
	FormLEA64           Form = "LEA r64, m"
	FormCallIndirect32  Form = "CALL r/m32"
	FormJumpIndirect32  Form = "JMP r/m32"
	FormMoveEAXMoffs32  Form = "MOV EAX, moffs32"
	FormMoveIndirect32  Form = "MOV r32, r/m32"
	FormMoveImmediate32 Form = "MOV r32, imm32"
)

type relocationAction uint8

const (
	relocationKeep relocationAction = iota
	relocationConsume
	relocationRetarget
)

// Site is one deterministic rewrite decision. RelocationIndex is -1 for a
// resolved local reference with no COFF relocation. Byte slices are defensive
// copies in plans returned by BuildPlan and Apply.
type Site struct {
	Pass              Pass
	Form              Form
	SectionIndex      int
	RelocationIndex   int
	SectionName       string
	RelocationOffset  uint32
	InstructionOffset uint32
	InstructionLength uint32
	Context           string
	Target            string
	Wrapper           string
	Symbol            string
	Original          []byte
	Replacement       []byte

	action         relocationAction
	resultSymbol   string
	resultType     uint16
	resultAddend   uint32
	writeAddend    bool
	originalType   uint16
	originalSymbol string
}

// Plan contains sites in upstream pass order and, within a pass, instruction
// address order.
type Plan struct {
	Machine coff.Machine
	Sites   []Site
}

// SiteError adds stable object location and pass context to a planning or
// encoding error.
type SiteError struct {
	Pass       Pass
	Section    string
	Relocation int
	Offset     uint32
	Symbol     string
	Err        error
}

func (e *SiteError) Error() string {
	relocation := ""
	if e.Relocation >= 0 {
		relocation = fmt.Sprintf(" relocation %d", e.Relocation)
	}
	symbol := ""
	if e.Symbol != "" {
		symbol = fmt.Sprintf(" symbol %q", e.Symbol)
	}
	return fmt.Sprintf("hookencode: %s section %s%s at %#x%s: %v", e.Pass, e.Section, relocation, e.Offset, symbol, e.Err)
}

func (e *SiteError) Unwrap() error { return e.Err }

func clonePlan(plan Plan) Plan {
	result := Plan{Machine: plan.Machine, Sites: make([]Site, len(plan.Sites))}
	for index, site := range plan.Sites {
		result.Sites[index] = site
		result.Sites[index].Original = append([]byte(nil), site.Original...)
		result.Sites[index].Replacement = append([]byte(nil), site.Replacement...)
	}
	return result
}
