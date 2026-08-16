// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

// Package spec parses and executes Crystal Palace-compatible specification files.
package spec

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

type tokenKind uint8

const (
	tokenVariable tokenKind = iota
	tokenString
	tokenConcat
)

type token struct {
	text string
	kind tokenKind
}

// Resolver resolves a late-bound percent variable.
type Resolver interface {
	Resolve(string) (string, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(string) (string, error)

func (f ResolverFunc) Resolve(name string) (string, error) { return f(name) }

// ResolvedArguments contains evaluated arguments and the percent variables used
// while evaluating them.
type ResolvedArguments struct {
	Args      []string
	Variables map[string]string
}

// Command is one parsed specification-language command.
type Command struct {
	original string
	name     string
	quote    rune
	options  map[string]struct{}
	tokens   []token
}

// ParseCommand parses a command using Crystal Palace's intentionally small,
// line-oriented lexer.
func ParseCommand(text string) *Command {
	return parseCommand(text, func(_ int, value string) string { return value })
}

func parseCommand(text string, replace func(int, string) string) *Command {
	c := &Command{
		original: text,
		quote:    '"',
		options:  make(map[string]struct{}),
	}
	c.scan(text, replace)
	return c
}

func (c *Command) scan(input string, replace func(int, string) string) {
	input = strings.TrimSpace(input)
	var current []rune
	runes := []rune(input)

	i := 0
	for ; i < len(runes); i++ {
		r := runes[i]
		switch {
		case unicode.IsSpace(r):
			c.name = replace(0, string(current))
			current = nil
			i++
			goto arguments
		case r == ',' && i+2 < len(runes) && unicode.IsSpace(runes[i+2]):
			c.name = replace(0, string(current))
			c.quote = runes[i+1]
			current = nil
			i += 3
			goto arguments
		case r == ',' && i+2 == len(runes):
			c.name = replace(0, string(current))
			c.quote = runes[i+1]
			current = nil
			i += 2
			goto arguments
		default:
			current = append(current, r)
		}
	}

	// A command without arguments is the whole trimmed input.
	if c.name == "" {
		c.name = replace(0, input)
	}
	return

arguments:
	for ; i < len(runes); i++ {
		r := runes[i]
		switch {
		case unicode.IsSpace(r):
			if len(current) > 0 {
				c.addToken(replace, string(current), false)
			}
			current = nil
		case r == ':':
			if len(current) > 0 {
				c.addToken(replace, string(current), false)
			}
			i++
			rest := strings.TrimSpace(string(runes[i:]))
			if rest != "" {
				c.addToken(replace, rest, true)
			}
			return
		case r == '#':
			if len(current) > 0 {
				c.addToken(replace, string(current), false)
			}
			return
		case r == c.quote && len(current) == 0:
			i++
			for ; i < len(runes) && runes[i] != c.quote; i++ {
				current = append(current, runes[i])
			}
			c.addToken(replace, string(current), true)
			current = nil
		default:
			current = append(current, r)
		}
	}
	if len(current) > 0 {
		c.addToken(replace, string(current), false)
	}
}

func (c *Command) addToken(replace func(int, string) string, value string, quoted bool) {
	value = replace(len(c.tokens)+1, value)
	switch {
	case quoted:
		c.tokens = append(c.tokens, token{text: value, kind: tokenString})
	case strings.HasPrefix(value, "+") && !strings.ContainsRune(value, ' '):
		c.options[value] = struct{}{}
	case strings.HasPrefix(value, "%") && !strings.ContainsRune(value, ' '):
		c.tokens = append(c.tokens, token{text: value, kind: tokenVariable})
	case value == "<>":
		c.tokens = append(c.tokens, token{text: value, kind: tokenConcat})
	default:
		c.tokens = append(c.tokens, token{text: value, kind: tokenString})
	}
}

// Original returns the source line from which the command was parsed.
func (c *Command) Original() string { return c.original }

// Name returns the command verb.
func (c *Command) Name() string { return c.name }

// QuoteCharacter returns the quote delimiter selected by the command.
func (c *Command) QuoteCharacter() rune { return c.quote }

// HasOptions reports whether the command contains any +option tokens.
func (c *Command) HasOptions() bool { return len(c.options) != 0 }

// HasOption reports whether a particular +option is present.
func (c *Command) HasOption(option string) bool {
	_, ok := c.options[option]
	return ok
}

// Options returns a stable copy of the command options.
func (c *Command) Options() []string {
	result := make([]string, 0, len(c.options))
	for option := range c.options {
		result = append(result, option)
	}
	sort.Strings(result)
	return result
}

// Arguments resolves percent variables and concatenation operators.
func (c *Command) Arguments(resolver Resolver) (ResolvedArguments, error) {
	result := ResolvedArguments{Variables: make(map[string]string)}
	if resolver == nil {
		resolver = ResolverFunc(func(name string) (string, error) { return name, nil })
	}

	for i := 0; i < len(c.tokens); i++ {
		t := c.tokens[i]
		switch t.kind {
		case tokenString:
			result.Args = append(result.Args, t.text)
		case tokenVariable:
			value, err := resolver.Resolve(t.text)
			if err != nil {
				return ResolvedArguments{}, err
			}
			result.Args = append(result.Args, value)
			result.Variables[t.text] = value
		case tokenConcat:
			if len(result.Args) == 0 {
				return ResolvedArguments{}, fmt.Errorf("concat operator is missing a left argument")
			}
			left := result.Args[len(result.Args)-1]
			result.Args = result.Args[:len(result.Args)-1]
			right := ""
			if i+1 < len(c.tokens) {
				i++
				next := c.tokens[i]
				switch next.kind {
				case tokenString:
					right = next.text
				case tokenVariable:
					value, err := resolver.Resolve(next.text)
					if err != nil {
						return ResolvedArguments{}, err
					}
					right = value
					result.Variables[next.text] = value
				case tokenConcat:
					return ResolvedArguments{}, fmt.Errorf("adjacent concat operators")
				}
			}
			result.Args = append(result.Args, left+right)
		}
	}
	return result, nil
}

// RawArguments resolves variables to their names, matching the parse-time view.
func (c *Command) RawArguments() []string {
	resolved, _ := c.Arguments(nil)
	return resolved.Args
}

// ArgumentTypes reports the parse-time type of each argument.
func (c *Command) ArgumentTypes() []string {
	result := make([]string, 0, len(c.tokens))
	for i := 0; i < len(c.tokens); i++ {
		t := c.tokens[i]
		var typ string
		if t.kind == tokenVariable {
			typ = "var"
		} else if t.kind == tokenString {
			typ = "string"
		} else {
			if len(result) == 0 {
				result = append(result, " <> ")
				continue
			}
			left := result[len(result)-1]
			result = result[:len(result)-1]
			right := ""
			if i+1 < len(c.tokens) {
				i++
				if c.tokens[i].kind == tokenVariable {
					right = "var"
				} else {
					right = "string"
				}
			}
			typ = left + " <> " + right
		}
		result = append(result, typ)
	}
	return result
}

// FullCommand reconstructs the command after variable resolution. +options are
// intentionally omitted, matching Crystal Palace.
func (c *Command) FullCommand(resolver Resolver) (string, error) {
	resolved, err := c.Arguments(resolver)
	if err != nil {
		return "", err
	}
	parts := []string{c.name}
	quote := string(c.quote)
	for _, arg := range resolved.Args {
		switch {
		case arg == "":
			parts = append(parts, quote+quote)
		case strings.ContainsRune(arg, ' '):
			parts = append(parts, quote+arg+quote)
		default:
			parts = append(parts, arg)
		}
	}
	return strings.Join(parts, " "), nil
}
