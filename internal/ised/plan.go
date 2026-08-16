// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package ised

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

var (
	// ErrInvalidProgram identifies inconsistent semantic instructions or COFF
	// locations supplied to BuildPlan or Apply.
	ErrInvalidProgram = errors.New("ised: invalid semantic program")

	// ErrSemanticDetailUnavailable is the explicit Capstone/Iced boundary.
	ErrSemanticDetailUnavailable = errors.New("ised: Iced-equivalent instruction detail is unavailable")

	// ErrUnsupportedMachine identifies architectures outside upstream ised's
	// x86 and x86-64 implementation.
	ErrUnsupportedMachine = errors.New("ised: unsupported machine")
)

// BoundaryError identifies the function, instruction, and typed semantic
// feature that prevents a safe rewrite.
type BoundaryError struct {
	Function string
	Section  string
	Offset   uint32
	Feature  string
	Err      error
}

func (e *BoundaryError) Error() string {
	location := e.Section
	if e.Function != "" {
		location += ":" + e.Function
	}
	if location == "" {
		location = "<program>"
	}
	return fmt.Sprintf("ised: %s at %s+%#x: %v", e.Feature, location, e.Offset, e.Err)
}

func (e *BoundaryError) Unwrap() error { return e.Err }

// RandomError reports an injectable shuffle source failure.
type RandomError struct{ Err error }

func (e *RandomError) Error() string { return fmt.Sprintf("ised: shuffle randomness: %v", e.Err) }
func (e *RandomError) Unwrap() error { return e.Err }

// Instruction is the Iced-equivalent semantic subset consumed by ised.
// Offset is section-relative. Form and Assembly must be the exact strings used
// as upstream match keys. The flag and bookend fields are analysis results, not
// values inferred from formatted operands.
type Instruction struct {
	Offset   uint32
	Bytes    []byte
	Form     string
	Assembly string

	HasRelocation bool
	PointerFix    bool
	DangerZone    bool
	FlagProducer  bool
	FlagConsumer  bool
	Bookend       bool
}

// Function is one pattern-matching boundary. Patterns never cross functions.
type Function struct {
	Name         string
	Section      string
	Instructions []Instruction
}

// Program is a deterministic semantic view of the executable instructions in
// a COFF object.
type Program struct {
	Machine   coff.Machine
	Functions []Function
}

// PlanOptions controls upstream selection context.
type PlanOptions struct {
	// Unwind enables prologue/epilogue bookend rejection.
	Unwind bool
	// Random supplies candidate shuffling bytes. crypto/rand.Reader is used
	// when nil. A caller wanting reproducible output should inject a reader.
	Random io.Reader
}

// Selection identifies one command selected for an instruction phase.
type Selection struct {
	CommandIndex int
	Content      []byte
}

// Edit contains at most one selected command for each upstream rewrite phase.
type Edit struct {
	Function         string
	Section          string
	InstructionIndex int
	Original         Instruction
	Prepend          *Selection
	Replace          *Selection
	Append           *Selection
}

// Plan is a deterministic snapshot once its injected randomness is fixed.
type Plan struct {
	Machine coff.Machine
	Edits   []Edit
}

type bagKind uint8

const (
	bagPrepend bagKind = iota
	bagReplace
	bagAppend
)

type instructionBags struct {
	prepend []int
	replace []int
	append  []int
}

type matchNode struct {
	next    map[string]*matchNode
	results []int
}

func newMatchNode() *matchNode { return &matchNode{next: make(map[string]*matchNode)} }

func (n *matchNode) add(patterns []string, command int) {
	current := n
	for _, pattern := range patterns {
		next := current.next[pattern]
		if next == nil {
			next = newMatchNode()
			current.next[pattern] = next
		}
		current = next
	}
	current.results = append(current.results, command)
}

// BuildPlan applies the upstream MatchTree and RewritePass selection semantics
// without mutating program or configuration.
func BuildPlan(program Program, configuration Configuration, options PlanOptions) (Plan, error) {
	if program.Machine != coff.MachineI386 && program.Machine != coff.MachineAMD64 {
		return Plan{}, fmt.Errorf("%w: %s", ErrUnsupportedMachine, program.Machine)
	}
	if configuration.IsEmpty() {
		return Plan{Machine: program.Machine, Edits: []Edit{}}, nil
	}
	if err := validateProgram(program); err != nil {
		return Plan{}, err
	}

	commands := configuration.commands
	root := newMatchNode()
	for index, command := range commands {
		root.add(command.Patterns, index)
	}
	random := options.Random
	if random == nil {
		random = cryptorand.Reader
	}

	plan := Plan{Machine: program.Machine, Edits: make([]Edit, 0)}
	for _, function := range program.Functions {
		bags := make([]instructionBags, len(function.Instructions))
		for start := range function.Instructions {
			walkMatches(root, function.Instructions, start, start, func(first, last, commandIndex int) {
				command := commands[commandIndex]
				target := last
				if command.Options.First {
					target = first
				}
				if command.Verb == VerbReplace {
					bags[target].replace = append(bags[target].replace, commandIndex)
				} else if command.Options.Before {
					bags[target].prepend = append(bags[target].prepend, commandIndex)
				} else {
					bags[target].append = append(bags[target].append, commandIndex)
				}
			})
		}

		for instructionIndex, instruction := range function.Instructions {
			edit := Edit{
				Function: function.Name, Section: function.Section, InstructionIndex: instructionIndex,
				Original: cloneInstruction(instruction),
			}
			var err error
			if !instruction.PointerFix {
				edit.Prepend, err = selectCommand(commands, bags[instructionIndex].prepend, bagPrepend, instruction, options.Unwind, random)
				if err != nil {
					return Plan{}, err
				}
			}
			if !instruction.HasRelocation {
				edit.Replace, err = selectCommand(commands, bags[instructionIndex].replace, bagReplace, instruction, options.Unwind, random)
				if err != nil {
					return Plan{}, err
				}
			}
			if !instruction.PointerFix {
				edit.Append, err = selectCommand(commands, bags[instructionIndex].append, bagAppend, instruction, options.Unwind, random)
				if err != nil {
					return Plan{}, err
				}
			}
			if edit.Prepend != nil || edit.Replace != nil || edit.Append != nil {
				plan.Edits = append(plan.Edits, edit)
			}
		}
	}
	return clonePlan(plan), nil
}

func walkMatches(root *matchNode, instructions []Instruction, start, position int, matched func(first, last, command int)) {
	if position >= len(instructions) {
		return
	}
	var walk func(*matchNode, int)
	walk = func(node *matchNode, index int) {
		if index >= len(instructions) {
			return
		}
		for _, key := range instructionKeys(instructions[index]) {
			next := node.next[key]
			if next == nil {
				continue
			}
			for _, command := range next.results {
				matched(start, index, command)
			}
			walk(next, index+1)
		}
	}
	walk(root, position)
}

func instructionKeys(instruction Instruction) []string {
	mnemonic := instruction.Form
	if index := strings.IndexByte(mnemonic, ' '); index >= 0 {
		mnemonic = mnemonic[:index]
	}
	return []string{instruction.Form, mnemonic, instruction.Assembly}
}

func selectCommand(commands []Command, candidates []int, kind bagKind, instruction Instruction, unwind bool, random io.Reader) (*Selection, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	shuffled := append([]int(nil), candidates...)
	if err := shuffle(shuffled, random); err != nil {
		return nil, &RandomError{Err: err}
	}
	// Upstream shuffles before rejecting an unwind bookend.
	if unwind && instruction.Bookend {
		return nil, nil
	}
	dangerous := instruction.DangerZone
	switch kind {
	case bagReplace:
		dangerous = dangerous || instruction.FlagProducer || instruction.FlagConsumer
	case bagPrepend:
		dangerous = dangerous || instruction.FlagConsumer
	case bagAppend:
		dangerous = dangerous || instruction.FlagProducer
	}
	for _, index := range shuffled {
		command := commands[index]
		if dangerous && !command.Options.Safe {
			continue
		}
		return &Selection{CommandIndex: index, Content: append([]byte(nil), command.Content...)}, nil
	}
	return nil, nil
}

func shuffle(values []int, random io.Reader) error {
	for index := len(values) - 1; index > 0; index-- {
		selected, err := randomIndex(random, index+1)
		if err != nil {
			return err
		}
		values[index], values[selected] = values[selected], values[index]
	}
	return nil
}

func randomIndex(random io.Reader, count int) (int, error) {
	if count <= 1 {
		return 0, nil
	}
	bound := uint64(count)
	limit := uint64(math.MaxUint64) - uint64(math.MaxUint64)%bound
	var data [8]byte
	for {
		if _, err := io.ReadFull(random, data[:]); err != nil {
			return 0, err
		}
		value := binary.LittleEndian.Uint64(data[:])
		if value < limit {
			return int(value % bound), nil
		}
	}
}

func validateProgram(program Program) error {
	functionNames := make(map[string]struct{}, len(program.Functions))
	type span struct {
		start uint32
		end   uint64
	}
	spans := make(map[string][]span)
	for functionIndex, function := range program.Functions {
		if function.Name == "" {
			return fmt.Errorf("%w: function %d has an empty name", ErrInvalidProgram, functionIndex)
		}
		if _, duplicate := functionNames[function.Name]; duplicate {
			return fmt.Errorf("%w: duplicate function %q", ErrInvalidProgram, function.Name)
		}
		functionNames[function.Name] = struct{}{}
		if function.Section == "" {
			return fmt.Errorf("%w: function %s has an empty section", ErrInvalidProgram, function.Name)
		}
		var previousEnd uint64
		for instructionIndex, instruction := range function.Instructions {
			boundary := func(feature string) error {
				return &BoundaryError{Function: function.Name, Section: function.Section, Offset: instruction.Offset, Feature: feature, Err: ErrSemanticDetailUnavailable}
			}
			if len(instruction.Bytes) == 0 || len(instruction.Bytes) > 15 {
				return fmt.Errorf("%w: %s instruction %d has %d bytes", ErrInvalidProgram, function.Name, instructionIndex, len(instruction.Bytes))
			}
			if instruction.Form == "" {
				return boundary("canonical opcode form")
			}
			if instruction.Assembly == "" {
				return boundary("MASM instruction rendering")
			}
			end := uint64(instruction.Offset) + uint64(len(instruction.Bytes))
			if end > uint64(math.MaxUint32)+1 {
				return fmt.Errorf("%w: %s instruction %d exceeds section address space", ErrInvalidProgram, function.Name, instructionIndex)
			}
			if instructionIndex != 0 && uint64(instruction.Offset) < previousEnd {
				return fmt.Errorf("%w: function %s instructions are not in non-overlapping address order", ErrInvalidProgram, function.Name)
			}
			previousEnd = end
			spans[function.Section] = append(spans[function.Section], span{start: instruction.Offset, end: end})
		}
	}
	for section, entries := range spans {
		sort.Slice(entries, func(i, j int) bool { return entries[i].start < entries[j].start })
		for index := 1; index < len(entries); index++ {
			if uint64(entries[index].start) < entries[index-1].end {
				return fmt.Errorf("%w: overlapping instructions in section %s at %#x", ErrInvalidProgram, section, entries[index].start)
			}
		}
	}
	return nil
}

func cloneInstruction(value Instruction) Instruction {
	value.Bytes = append([]byte(nil), value.Bytes...)
	return value
}

func cloneProgram(value Program) Program {
	result := Program{Machine: value.Machine, Functions: make([]Function, len(value.Functions))}
	for functionIndex, function := range value.Functions {
		result.Functions[functionIndex] = Function{Name: function.Name, Section: function.Section, Instructions: make([]Instruction, len(function.Instructions))}
		for instructionIndex, instruction := range function.Instructions {
			result.Functions[functionIndex].Instructions[instructionIndex] = cloneInstruction(instruction)
		}
	}
	return result
}

func cloneSelection(value *Selection) *Selection {
	if value == nil {
		return nil
	}
	return &Selection{CommandIndex: value.CommandIndex, Content: append([]byte(nil), value.Content...)}
}

func clonePlan(value Plan) Plan {
	result := Plan{Machine: value.Machine, Edits: make([]Edit, len(value.Edits))}
	for index, edit := range value.Edits {
		result.Edits[index] = edit
		result.Edits[index].Original = cloneInstruction(edit.Original)
		result.Edits[index].Prepend = cloneSelection(edit.Prepend)
		result.Edits[index].Replace = cloneSelection(edit.Replace)
		result.Edits[index].Append = cloneSelection(edit.Append)
	}
	return result
}
