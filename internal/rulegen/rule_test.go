// SPDX-License-Identifier: GPL-3.0-only

package rulegen

import (
	"reflect"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestRuleRawAndRuleWildcardCallsAndCache(t *testing.T) {
	instructions := []RuleInstruction{
		{Instruction: x86.Instruction{Address: 0, Bytes: []byte{0x31, 0xc0}, Mnemonic: "xor", Operands: "eax, eax"}, Score: 2},
		{Instruction: x86.Instruction{Address: 2, Bytes: []byte{0xe8, 1, 2, 3, 4}, Mnemonic: "call", Operands: "0x4030208"}},
	}
	raw, err := NewRuleRaw(instructions)
	if err != nil {
		t.Fatal(err)
	}
	if raw.TotalBytes() != 7 || raw.TotalValidBytes() != 3 || raw.Score() != 6 {
		t.Fatalf("raw totals = bytes %d valid %d score %d", raw.TotalBytes(), raw.TotalValidBytes(), raw.Score())
	}
	wantMask := []bool{false, false, false, true, true, true, true}
	if !reflect.DeepEqual(raw.Wildcards(), wantMask) {
		t.Fatalf("wildcards = %#v, want %#v", raw.Wildcards(), wantMask)
	}
	rule, err := NewRule(instructions)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rule.Content(), []byte{0x31, 0xc0, 0xe8, 0, 0, 0, 0}; !reflect.DeepEqual(got, want) {
		t.Fatalf("content = %x, want %x", got, want)
	}

	// The model owns all mutable input and output slices.
	instructions[0].Instruction.Bytes[0] = 0xff
	content := rule.Content()
	content[0] = 0xee
	if got := rule.Content()[0]; got != 0x31 {
		t.Fatalf("cached content mutated to %#x", got)
	}
}

func TestRuleIdentityIncludesWildcardLocations(t *testing.T) {
	first, err := NewRule([]RuleInstruction{{
		Instruction: x86.Instruction{Bytes: []byte{1, 2}}, Wildcards: []bool{false, true}, Score: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRule([]RuleInstruction{{
		Instruction: x86.Instruction{Bytes: []byte{1, 9}}, Wildcards: []bool{false, true}, Score: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	third, err := NewRule([]RuleInstruction{{
		Instruction: x86.Instruction{Bytes: []byte{1, 0}}, Wildcards: []bool{true, false}, Score: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(second) {
		t.Fatal("rules with equal normalized content and masks did not compare equal")
	}
	if first.Equal(third) {
		t.Fatal("rules with different wildcard positions compared equal")
	}
}

func TestNewRuleRejectsMalformedInstruction(t *testing.T) {
	tests := []RuleInstruction{
		{Instruction: x86.Instruction{}},
		{Instruction: x86.Instruction{Bytes: []byte{1, 2}}, Wildcards: []bool{true}},
	}
	for _, instruction := range tests {
		if _, err := NewRule([]RuleInstruction{instruction}); err == nil {
			t.Fatalf("NewRule(%#v) succeeded", instruction)
		}
	}
}

func TestRuleOptimizerSelectsHighestScoringContiguousTrain(t *testing.T) {
	input := []RuleInstruction{
		{Instruction: x86.Instruction{Bytes: []byte{0x10}}, Score: 1},
		{Instruction: x86.Instruction{Bytes: []byte{0x20}}, Score: 10},
		{Instruction: x86.Instruction{Bytes: []byte{0x30}}, Score: 3},
		{Instruction: x86.Instruction{Bytes: []byte{0x40}}, Score: 1},
	}
	rule, err := NewRule(input)
	if err != nil {
		t.Fatal(err)
	}
	optimizer, err := NewRuleOptimizer(2)
	if err != nil {
		t.Fatal(err)
	}
	optimized, err := optimizer.Optimize(rule)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := optimized.Content(), []byte{0x20, 0x30}; !reflect.DeepEqual(got, want) {
		t.Fatalf("optimized content = %x, want %x", got, want)
	}
	if optimized.Score() != 13 || optimized.TotalValidBytes() != 2 {
		t.Fatalf("optimized totals = score %d valid %d", optimized.Score(), optimized.TotalValidBytes())
	}
}

func TestRuleOptimizerTieKeepsEarliestAndRejectsBadBudget(t *testing.T) {
	rule, err := NewRule([]RuleInstruction{
		{Instruction: x86.Instruction{Bytes: []byte{1}}, Score: 1},
		{Instruction: x86.Instruction{Bytes: []byte{2}}, Score: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	optimized, err := (RuleOptimizer{MaxLength: 1}).Optimize(rule)
	if err != nil {
		t.Fatal(err)
	}
	if got := optimized.Content(); !reflect.DeepEqual(got, []byte{1}) {
		t.Fatalf("tie chose %x, want earliest", got)
	}
	if _, err := NewRuleOptimizer(0); err == nil {
		t.Fatal("NewRuleOptimizer(0) succeeded")
	}
}
