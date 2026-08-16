// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package ised

import (
	"errors"
	"fmt"
)

// Verb is an upstream ised operation.
type Verb string

const (
	VerbInsert  Verb = "insert"
	VerbReplace Verb = "replace"
)

// CommandOptions is the validated option set attached to one ised command.
type CommandOptions struct {
	Before bool
	After  bool
	First  bool
	Last   bool
	Split  bool
	Safe   bool
}

// Command is one validated instruction rewrite. Content already includes the
// synthetic EB 00 requested by +split.
type Command struct {
	Verb     Verb
	Patterns []string
	Variable string
	Options  CommandOptions
	Content  []byte
}

// Directive is one replayable ised command plus its resolved byte variable.
type Directive struct {
	Arguments []string
	Options   []string
	Content   []byte
}

var ErrInvalidCommand = errors.New("ised: invalid command")

// CommandError preserves the upstream validation diagnostic while supporting
// errors.Is(err, ErrInvalidCommand).
type CommandError struct{ Message string }

func (e *CommandError) Error() string { return e.Message }
func (e *CommandError) Unwrap() error { return ErrInvalidCommand }

// ParseDirective translates resolved specification arguments and option tokens
// into one command. Arguments retain upstream's case-sensitive interpretation.
func ParseDirective(arguments, optionTokens []string, content []byte) (Command, error) {
	if len(arguments) == 0 || (arguments[0] != string(VerbInsert) && arguments[0] != string(VerbReplace)) {
		verb := ""
		if len(arguments) != 0 {
			verb = arguments[0]
		}
		return Command{}, invalidCommand(fmt.Sprintf("ised: Invalid verb '%s'. Use insert or replace", verb))
	}
	if len(arguments) < 2 || arguments[len(arguments)-1] == "" {
		return Command{}, invalidCommand("ised: Specify a variable $VAR as the last parameter")
	}
	if len(arguments) < 3 {
		return Command{}, invalidCommand("ised: Missing pattern arguments. Specify as \"push rbx\" (specific) or \"PUSH r64\" (generic)")
	}
	options, err := parseOptions(optionTokens)
	if err != nil {
		return Command{}, err
	}
	if options.First && options.Last {
		return Command{}, invalidCommand("ised: both +first and +last set. Pick one. I can't act on both.")
	}
	if options.Before && options.After {
		return Command{}, invalidCommand("ised: both +before and +after set. Pick one. I can't act on both.")
	}

	command := Command{
		Verb: Verb(arguments[0]), Patterns: append([]string(nil), arguments[1:len(arguments)-1]...),
		Variable: arguments[len(arguments)-1], Options: options, Content: append([]byte(nil), content...),
	}
	if options.Split {
		jump := []byte{0xeb, 0x00}
		if options.First || options.Before {
			command.Content = append(jump, command.Content...)
		} else {
			command.Content = append(command.Content, jump...)
		}
	}
	return command, nil
}

func parseOptions(tokens []string) (CommandOptions, error) {
	var result CommandOptions
	for _, token := range tokens {
		switch token {
		case "+before":
			result.Before = true
		case "+after":
			result.After = true
		case "+first":
			result.First = true
		case "+last":
			result.Last = true
		case "+split":
			result.Split = true
		case "+safe":
			result.Safe = true
		default:
			return CommandOptions{}, invalidCommand(fmt.Sprintf("ised: Invalid option '%s'", token))
		}
	}
	return result, nil
}

func invalidCommand(message string) error { return &CommandError{Message: message} }

func cloneCommand(value Command) Command {
	value.Patterns = append([]string(nil), value.Patterns...)
	value.Content = append([]byte(nil), value.Content...)
	return value
}
