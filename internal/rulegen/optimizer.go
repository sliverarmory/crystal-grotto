// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package rulegen

import "fmt"

// RuleOptimizer selects the highest-scoring contiguous instruction train that
// fits within a valid-byte budget. Score ties retain the earliest train.
type RuleOptimizer struct {
	MaxLength int
}

// NewRuleOptimizer validates a maximum valid-byte length.
func NewRuleOptimizer(maxLength int) (RuleOptimizer, error) {
	if maxLength <= 0 {
		return RuleOptimizer{}, fmt.Errorf("rulegen: maximum rule length must be positive, got %d", maxLength)
	}
	return RuleOptimizer{MaxLength: maxLength}, nil
}

// Optimize applies the upstream greedy-per-start train selection.
func (o RuleOptimizer) Optimize(rule Rule) (Rule, error) {
	if o.MaxLength <= 0 {
		return Rule{}, fmt.Errorf("rulegen: maximum rule length must be positive, got %d", o.MaxLength)
	}
	if rule.TotalValidBytes() < o.MaxLength {
		return rule, nil
	}
	instructions := rule.Instructions()
	bestStart, bestEnd, bestScore := 0, 0, -1
	for start := range instructions {
		length, score := 0, 0
		end := start
		for end < len(instructions) {
			candidateLength := validInstructionBytes(instructions[end])
			if length+candidateLength > o.MaxLength {
				break
			}
			length += candidateLength
			score += instructions[end].Score
			end++
		}
		if score > bestScore {
			bestStart, bestEnd, bestScore = start, end, score
		}
	}
	if bestEnd <= bestStart {
		return rule, nil
	}
	return NewRule(instructions[bestStart:bestEnd])
}

func validInstructionBytes(instruction RuleInstruction) int {
	valid := 0
	for _, wildcard := range instruction.Wildcards {
		if !wildcard {
			valid++
		}
	}
	return valid
}
