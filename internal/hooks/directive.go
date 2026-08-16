// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package hooks

import (
	"fmt"
)

// DirectiveKind is one supported Crystal Palace configuration command.
type DirectiveKind string

const (
	Attach      DirectiveKind = "attach"
	Redirect    DirectiveKind = "redirect"
	AddHook     DirectiveKind = "addhook"
	FilterHooks DirectiveKind = "filterhooks"
	Preserve    DirectiveKind = "preserve"
	Protect     DirectiveKind = "protect"
	OptOut      DirectiveKind = "optout"
	Intrinsic   DirectiveKind = "intrinsic"
	Catch       DirectiveKind = "catch"
)

// Directive is an immutable parsed command. ResourceRef identifies the
// environment byte value used by intrinsic and filterhooks.
type Directive struct {
	kind        DirectiveKind
	arguments   []string
	resourceRef string
}

// Parse validates command arity and returns a defensive representation.
func Parse(command string, arguments []string) (Directive, error) {
	kind := DirectiveKind(command)
	minimum, maximum := 0, 0
	switch kind {
	case Attach, Redirect, Preserve, OptOut, Intrinsic, Catch:
		minimum, maximum = 2, 2
	case AddHook:
		minimum, maximum = 1, 2
	case FilterHooks, Protect:
		minimum, maximum = 1, 1
	default:
		return Directive{}, fmt.Errorf("hooks: unsupported directive %q", command)
	}
	if len(arguments) < minimum || len(arguments) > maximum {
		if minimum == maximum {
			return Directive{}, fmt.Errorf("hooks: %s expects %d arguments, got %d", command, minimum, len(arguments))
		}
		return Directive{}, fmt.Errorf("hooks: %s expects %d to %d arguments, got %d", command, minimum, maximum, len(arguments))
	}
	result := Directive{kind: kind, arguments: append([]string(nil), arguments...)}
	if kind == Intrinsic {
		result.resourceRef = arguments[1]
	} else if kind == FilterHooks {
		result.resourceRef = arguments[0]
	}
	return result, nil
}

func (d Directive) Kind() DirectiveKind { return d.kind }

// Arguments returns a defensive copy in specification order.
func (d Directive) Arguments() []string {
	return append([]string(nil), d.arguments...)
}

func (d Directive) NeedsBytes() bool {
	return d.kind == Intrinsic || d.kind == FilterHooks
}

func (d Directive) ResourceRef() string { return d.resourceRef }

// ByteResolver resolves a specification environment reference to bytes.
type ByteResolver func(reference string) ([]byte, error)
