// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package rulegen

import (
	"bytes"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

// RuleInstruction couples one decoded instruction with bytes which must be
// wildcarded and its uniqueness score. Wildcards is instruction-relative.
// A non-positive Score selects the conservative built-in score.
type RuleInstruction struct {
	Instruction x86.Instruction
	Wildcards   []bool
	Score       int
}

// RuleRaw is the uncached form of a candidate YARA byte string.
type RuleRaw struct {
	instructions []RuleInstruction
}

// NewRuleRaw validates and takes defensive copies of decoded instructions.
func NewRuleRaw(instructions []RuleInstruction) (RuleRaw, error) {
	result := RuleRaw{instructions: make([]RuleInstruction, len(instructions))}
	for index, instruction := range instructions {
		if len(instruction.Instruction.Bytes) == 0 {
			return RuleRaw{}, fmt.Errorf("rulegen: instruction %d has no bytes", index)
		}
		if instruction.Wildcards != nil && len(instruction.Wildcards) != len(instruction.Instruction.Bytes) {
			return RuleRaw{}, fmt.Errorf("rulegen: instruction %d has %d wildcard flags for %d bytes", index, len(instruction.Wildcards), len(instruction.Instruction.Bytes))
		}
		result.instructions[index] = cloneRuleInstruction(instruction)
		if result.instructions[index].Wildcards == nil {
			result.instructions[index].Wildcards = make([]bool, len(instruction.Instruction.Bytes))
		}
		if isE8Call(result.instructions[index].Instruction) {
			for offset := 1; offset < 5; offset++ {
				result.instructions[index].Wildcards[offset] = true
			}
		}
		if result.instructions[index].Score <= 0 {
			result.instructions[index].Score = conservativeScore(result.instructions[index].Instruction)
		}
	}
	return result, nil
}

// Instructions returns defensive copies in source order.
func (r RuleRaw) Instructions() []RuleInstruction {
	result := make([]RuleInstruction, len(r.instructions))
	for index, instruction := range r.instructions {
		result[index] = cloneRuleInstruction(instruction)
	}
	return result
}

// TotalBytes returns the encoded byte count.
func (r RuleRaw) TotalBytes() int {
	total := 0
	for _, instruction := range r.instructions {
		total += len(instruction.Instruction.Bytes)
	}
	return total
}

// TotalValidBytes returns the count after relocation and call wildcards.
func (r RuleRaw) TotalValidBytes() int {
	total := 0
	for _, instruction := range r.instructions {
		for _, wildcard := range instruction.Wildcards {
			if !wildcard {
				total++
			}
		}
	}
	return total
}

// Score returns the sum of the per-instruction scores.
func (r RuleRaw) Score() int {
	total := 0
	for _, instruction := range r.instructions {
		total += instruction.Score
	}
	return total
}

// Content concatenates the original instruction bytes.
func (r RuleRaw) Content() []byte {
	result := make([]byte, 0, r.TotalBytes())
	for _, instruction := range r.instructions {
		result = append(result, instruction.Instruction.Bytes...)
	}
	return result
}

// Wildcards concatenates instruction-relative wildcard masks.
func (r RuleRaw) Wildcards() []bool {
	result := make([]bool, 0, r.TotalBytes())
	for _, instruction := range r.instructions {
		result = append(result, instruction.Wildcards...)
	}
	return result
}

// Rule is the cached, immutable representation used for de-duplication,
// optimization, and printing. Wildcarded content bytes are normalized to zero
// to match Crystal Palace equality semantics.
type Rule struct {
	raw        RuleRaw
	content    []byte
	wildcards  []bool
	totalBytes int
	validBytes int
	score      int
}

// NewRule constructs a cached rule.
func NewRule(instructions []RuleInstruction) (Rule, error) {
	raw, err := NewRuleRaw(instructions)
	if err != nil {
		return Rule{}, err
	}
	content := raw.Content()
	wildcards := raw.Wildcards()
	for index, wildcard := range wildcards {
		if wildcard {
			content[index] = 0
		}
	}
	return Rule{
		raw:        raw,
		content:    content,
		wildcards:  wildcards,
		totalBytes: raw.TotalBytes(),
		validBytes: raw.TotalValidBytes(),
		score:      raw.Score(),
	}, nil
}

func (r Rule) Instructions() []RuleInstruction { return r.raw.Instructions() }
func (r Rule) TotalBytes() int                 { return r.totalBytes }
func (r Rule) TotalValidBytes() int            { return r.validBytes }
func (r Rule) Score() int                      { return r.score }
func (r Rule) Content() []byte                 { return append([]byte(nil), r.content...) }
func (r Rule) Wildcards() []bool               { return append([]bool(nil), r.wildcards...) }

// Equal implements upstream rule identity: normalized content plus the
// wildcard bitmap.
func (r Rule) Equal(other Rule) bool {
	return bytes.Equal(r.content, other.content) && equalBools(r.wildcards, other.wildcards)
}

func cloneRuleInstruction(source RuleInstruction) RuleInstruction {
	result := source
	result.Instruction.Bytes = append([]byte(nil), source.Instruction.Bytes...)
	if source.Instruction.Detail != nil {
		detail := *source.Instruction.Detail
		result.Instruction.Detail = &detail
	}
	result.Wildcards = append([]bool(nil), source.Wildcards...)
	return result
}

func conservativeScore(instruction x86.Instruction) int {
	if isE8Call(instruction) {
		return 4
	}
	return 1
}

func isE8Call(instruction x86.Instruction) bool {
	return len(instruction.Bytes) == 5 && instruction.Bytes[0] == 0xe8
}

func equalBools(left, right []bool) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
