// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package safety

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var (
	// ErrUnproven identifies an input for which the helper call graph could not
	// be proven complete. Callers must treat this as a failed safety check.
	ErrUnproven = errors.New("safety: call graph safety cannot be proven")

	// ErrDangerousDprintf identifies the unsafe helper-to-dprintf condition
	// rejected by Crystal Palace's DangerWalk pass.
	ErrDangerousDprintf = errors.New("safety: dprintf is unsafe from helper context")
)

// DisassemblerFactory opens an x86 decoder for one graph build. A decoder
// returned by a factory is owned and closed by BuildGraph.
type DisassemblerFactory func(context.Context, x86.Mode) (x86.Disassembler, error)

// Options controls instruction decoding. Supplying neither field uses the
// portable Capstone backend. Disassembler is caller-owned and is not closed;
// Factory results are owned by BuildGraph. Supplying both is invalid.
type Options struct {
	Disassembler x86.Disassembler
	Factory      DisassemblerFactory
}

// AnalysisError describes why a complete conservative call graph could not be
// constructed. It matches ErrUnproven and also unwraps its underlying cause.
type AnalysisError struct {
	Stage     string
	Function  string
	Offset    uint32
	HasOffset bool
	Err       error
}

func (e *AnalysisError) Error() string {
	if e == nil {
		return ErrUnproven.Error()
	}
	var location string
	if e.Function != "" {
		location = " in " + e.Function
	}
	if e.HasOffset {
		location += fmt.Sprintf(" at .text+%#x", e.Offset)
	}
	stage := e.Stage
	if stage == "" {
		stage = "analysis"
	}
	cause := e.Err
	if cause == nil {
		cause = ErrUnproven
	}
	return fmt.Sprintf("safety: cannot prove helper call graph during %s%s: %v", stage, location, cause)
}

func (e *AnalysisError) Unwrap() []error {
	if e == nil || e.Err == nil || errors.Is(e.Err, ErrUnproven) {
		return []error{ErrUnproven}
	}
	return []error{ErrUnproven, e.Err}
}

// DangerError reports the first unsafe edge in upstream traversal order.
// Chain contains the helper root through the function containing the dprintf
// reference; like upstream, it does not append dprintf itself.
type DangerError struct {
	Root    string
	Parent  string
	Symbol  string
	Chain   []string
	Machine coff.Machine
}

func (e *DangerError) Error() string {
	if e == nil {
		return ErrDangerousDprintf.Error()
	}
	message := "Don't call dprintf from dfr/fixptrs/fixbss. OutputDebugStringA's message propagation (SEHs) can corrupt from these contexts. (" + strings.Join(e.Chain, " -> ") + ")"
	findFunction := "findFunctionByHash"
	if e.Machine == coff.MachineI386 {
		findFunction = "_findFunctionByHash"
	}
	for _, function := range e.Chain {
		if function == findFunction {
			return message + " [Use protect \"" + findFunction + "\" to opt this function out of attach hooks.]"
		}
	}
	return message
}

func (e *DangerError) Unwrap() error { return ErrDangerousDprintf }

// EdgeKind describes the evidence that established a graph edge.
type EdgeKind string

const (
	EdgeDirectCall       EdgeKind = "direct-call"
	EdgeDirectJump       EdgeKind = "direct-jump"
	EdgeRIPReference     EdgeKind = "rip-reference"
	EdgeRelocation       EdgeKind = "relocation"
	EdgeReferencePointer EdgeKind = "reference-pointer"
)

// Edge is a deterministic local call/reference graph edge.
type Edge struct {
	From   string
	To     string
	Offset uint32
	Kind   EdgeKind
}

// Report describes a successful walk. Roots and Visited retain caller and
// traversal order respectively; each returned slice owns its storage.
type Report struct {
	Roots   []string
	Visited []string
}

// Graph is an immutable, reusable call/reference graph for one normalized
// object. Its slices and maps are kept private so concurrent checks are safe.
type Graph struct {
	machine   coff.Machine
	functions []string
	edges     []Edge
	adjacency map[string][]Edge
	rootable  map[string]bool
}

// Machine returns the architecture for which the graph was built.
func (g *Graph) Machine() coff.Machine {
	if g == nil {
		return 0
	}
	return g.machine
}

// Functions returns graph nodes in normalized .text order.
func (g *Graph) Functions() []string {
	if g == nil {
		return nil
	}
	return append([]string(nil), g.functions...)
}

// Edges returns graph edges in source/instruction discovery order.
func (g *Graph) Edges() []Edge {
	if g == nil {
		return nil
	}
	return append([]Edge(nil), g.edges...)
}
