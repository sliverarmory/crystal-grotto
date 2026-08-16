// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package ised

import "fmt"

// Configuration is an immutable, concurrent-read-safe rewrite snapshot.
type Configuration struct{ commands []Command }

// EmptyConfiguration returns a configuration with no ised rewrites.
func EmptyConfiguration() Configuration { return Configuration{} }

// IsEmpty reports whether the upstream Rewrite pass would be skipped.
func (c Configuration) IsEmpty() bool { return len(c.commands) == 0 }

// Commands returns defensive copies in declaration order.
func (c Configuration) Commands() []Command { return cloneCommands(c.commands) }

// Replay parses and appends directives transactionally. No partially updated
// configuration is returned if any directive is invalid.
func Replay(base Configuration, directives []Directive) (Configuration, error) {
	next := Configuration{commands: cloneCommands(base.commands)}
	for index, directive := range directives {
		command, err := ParseDirective(directive.Arguments, directive.Options, directive.Content)
		if err != nil {
			return Configuration{}, fmt.Errorf("ised directive %d: %w", index, err)
		}
		next.commands = append(next.commands, command)
	}
	return next, nil
}

func cloneCommands(values []Command) []Command {
	result := make([]Command, len(values))
	for index, value := range values {
		result[index] = cloneCommand(value)
	}
	return result
}
