// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package rulegen

import (
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/binutil"
)

const (
	defaultMaxRules  = 10
	defaultAgreement = 5
	defaultMinLength = 10
	defaultMaxLength = 16
)

// Args is the parsed form of Crystal Palace's positional rule arguments:
// name, maximum rule count, minimum agreement, valid-byte range, and an
// optional comma-separated function allow-list.
type Args struct {
	Name      string
	MaxRules  int
	Agreement int
	MinLength int
	MaxLength int
	Functions []string
}

// DefaultArgs returns the upstream defaults.
func DefaultArgs() Args {
	return Args{
		MaxRules:  defaultMaxRules,
		Agreement: defaultAgreement,
		MinLength: defaultMinLength,
		MaxLength: defaultMaxLength,
	}
}

// ParseArgs parses RuleGenArgs-compatible positional arguments. Like the
// upstream ArgParser, values after the fifth positional argument are ignored.
func ParseArgs(arguments []string) (Args, error) {
	result := DefaultArgs()
	if len(arguments) > 0 {
		result.Name = arguments[0]
	}
	if len(arguments) > 1 {
		value, err := binutil.ParseInt32(arguments[1])
		if err != nil || value == -1 {
			return Args{}, fmt.Errorf("maxrules must be integer: %s", arguments[1])
		}
		result.MaxRules = int(value)
	}
	if len(arguments) > 2 {
		value, err := binutil.ParseInt32(arguments[2])
		if err != nil || value == -1 {
			return Args{}, fmt.Errorf("minagree must be integer: %s", arguments[2])
		}
		result.Agreement = int(value)
	}
	if len(arguments) > 3 {
		value, err := binutil.ParseRange(arguments[3])
		if err != nil {
			return Args{}, err
		}
		result.MinLength = int(value.Min)
		result.MaxLength = int(value.Max)
	}
	if len(arguments) > 4 {
		result.Functions = binutil.SplitSet(arguments[4])
	}
	if err := result.Validate(); err != nil {
		return Args{}, err
	}
	return result, nil
}

// Validate validates values supplied programmatically. It intentionally keeps
// the upstream acceptance of negative integers other than -1; a non-positive
// MaxRules simply disables output.
func (a Args) Validate() error {
	if a.MaxRules == -1 {
		return fmt.Errorf("maxrules must be integer: %d", a.MaxRules)
	}
	if a.Agreement == -1 {
		return fmt.Errorf("minagree must be integer: %d", a.Agreement)
	}
	if a.MinLength >= a.MaxLength {
		return fmt.Errorf("Invalid range. %d >= %d from %d-%d", a.MinLength, a.MaxLength, a.MinLength, a.MaxLength)
	}
	if a.MaxRules > 0 && a.Agreement > a.MaxRules {
		return fmt.Errorf("agreement %d is larger than max rules %d. That won't fly", a.Agreement, a.MaxRules)
	}
	return nil
}

// Targets reports whether a function passes the optional allow-list.
func (a Args) Targets(symbol string) bool {
	if len(a.Functions) == 0 {
		return true
	}
	for _, function := range a.Functions {
		if function == symbol {
			return true
		}
	}
	return false
}
