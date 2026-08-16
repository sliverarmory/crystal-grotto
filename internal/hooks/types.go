// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package hooks

import (
	"errors"
	"fmt"
	"strings"

	crystalhash "github.com/sliverarmory/crystal-grotto/internal/hash"
)

var (
	ErrNilContext         = errors.New("hooks: nil context")
	ErrNilObject          = errors.New("hooks: nil COFF object")
	ErrNilModel           = errors.New("hooks: nil model")
	ErrUnsupportedMachine = errors.New("hooks: unsupported machine")
	ErrEncoderRequired    = errors.New("hooks: architecture-aware encoder is required")
)

// Hook is one declaration in a target's wrapper chain.
type Hook struct {
	Target        string
	Wrapper       string
	DeclaredIndex int
}

func (h Hook) String() string { return "Hook " + h.Target + " -> " + h.Wrapper }

// ModuleFunction is the parsed MODULE$Function representation used by attach
// and addhook.
type ModuleFunction struct {
	Module   string
	Function string
}

// ParseModuleFunction mirrors Java String.split behavior relevant to the
// upstream ModFunc parser. Extra dollar-separated components are ignored.
func ParseModuleFunction(target string) (ModuleFunction, error) {
	parts := strings.Split(target, "$")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) < 2 {
		return ModuleFunction{}, fmt.Errorf("%s is not in MODULE$Function format", target)
	}
	return ModuleFunction{Module: parts[0], Function: parts[1]}, nil
}

// Target returns the canonical spelling used by addhook filtering.
func (m ModuleFunction) Target() string {
	return strings.ToUpper(m.Module) + "$" + m.Function
}

// ResolveHook is one addhook entry. Self means its wrapper is selected from
// the external attach chain for the call-site context.
type ResolveHook struct {
	Target   string
	Module   string
	Function string
	Wrapper  string
	Self     bool
}

func (r ResolveHook) FunctionHash() uint32 {
	return crystalhash.ROR13{}.Sum32([]byte(r.Function))
}

// HookPlan is the deterministic result of attach or redirect routing. A
// matched plan requires an encoder/rebuilder before it changes program bytes.
type HookPlan struct {
	Kind            DirectiveKind
	Context         string
	Target          string
	Wrapper         string
	Matched         bool
	RequiresEncoder bool
}

// EncodingError makes the unsupported binary step explicit to consumers that
// do not have an encoder. An unmatched plan needs no transformation.
func (p HookPlan) EncodingError() error {
	if !p.Matched || !p.RequiresEncoder {
		return nil
	}
	return fmt.Errorf("%w: %s %s -> %s in %s", ErrEncoderRequired, p.Kind, p.Target, p.Wrapper, p.Context)
}

// HookChainSnapshot is one deterministic configuration snapshot.
type HookChainSnapshot struct {
	Target string
	Hooks  []Hook
}

type SelectionSnapshot struct {
	Target string
	Values []string
}

type IntrinsicSnapshot struct {
	Symbol  string
	Content []byte
}

type CatchSnapshot struct {
	Function string
	Handler  string
}

// Snapshot contains defensive, deterministic configuration data.
type Snapshot struct {
	Machine      string
	External     []HookChainSnapshot
	Local        []HookChainSnapshot
	Preserved    []SelectionSnapshot
	OptOut       []SelectionSnapshot
	Protected    []string
	ResolveHooks []ResolveHook
	Intrinsics   []IntrinsicSnapshot
	Catches      []CatchSnapshot
}
