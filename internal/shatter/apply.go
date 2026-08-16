// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package shatter

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

var applyMu sync.Mutex

// Apply transactionally applies one upstream-compatible +shatter pass to
// object. Randomness may be consumed on failure, but the COFF graph changes
// only after layout, branch, symbol, relocation, and metadata repair succeeds.
//
// Upstream runs this after rule generation, +mutate, ISED rewrites, and
// +regdance, as the final BTF rebuild with jump healing enabled. It must run
// before any later binary export and cannot be combined with +unwind.
func Apply(ctx context.Context, object *coff.Object, options Options) (Report, error) {
	if err := validateApplyInputs(ctx, object); err != nil {
		return Report{}, err
	}
	random, err := newBoundedRandom(options)
	if err != nil {
		return Report{}, err
	}
	return run(ctx, object, random, true)
}

// Heal transactionally performs upstream ShatterPass's final no-filter
// rebuild. It preserves original block order and consumes no randomness, while
// applying the same direct-jump healing and Iced-style branch relaxation used
// after ISED rewrites when neither +shatter nor +blockparty is selected.
func Heal(ctx context.Context, object *coff.Object) (Report, error) {
	if err := validateApplyInputs(ctx, object); err != nil {
		return Report{}, err
	}
	return run(ctx, object, nil, false)
}

func validateApplyInputs(ctx context.Context, object *coff.Object) error {
	if ctx == nil {
		return errors.New("shatter: nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("shatter: %w", err)
	}
	if object == nil {
		return errors.New("shatter: nil COFF object")
	}
	return nil
}

func run(ctx context.Context, object *coff.Object, random boundedRandom, distribute bool) (Report, error) {
	// coff.Object is a mutable pointer graph without internal synchronization.
	applyMu.Lock()
	defer applyMu.Unlock()

	p, err := newPlan(ctx, object)
	if err != nil {
		return Report{}, err
	}
	defer func() { _ = p.decoder.Close(context.Background()) }()
	if err := p.buildBlocks(ctx); err != nil {
		return Report{}, err
	}
	if distribute {
		if err := p.distributeBlocks(ctx, random); err != nil {
			return Report{}, err
		}
	} else {
		if err := p.preserveBlocks(ctx); err != nil {
			return Report{}, err
		}
	}
	if err := p.buildFragments(ctx); err != nil {
		return Report{}, err
	}
	if err := p.finish(ctx); err != nil {
		return Report{}, err
	}
	return p.report, nil
}

func (p *plan) preserveBlocks(ctx context.Context) error {
	for _, function := range p.functions {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("shatter: %w", err)
		}
		function.physical = append([]*block(nil), function.blocks...)
		layout := FunctionLayout{Name: function.name}
		for _, next := range function.physical {
			layout.Blocks = append(layout.Blocks, BlockAssignment{
				SourceFunction: function.name,
				HomeFunction:   function.name,
				Start:          next.start,
			})
		}
		p.report.Layouts = append(p.report.Layouts, layout)
	}
	return nil
}

func (p *plan) buildBlocks(ctx context.Context) error {
	targets := make(map[uint32]struct{})
	for _, entry := range p.instructions {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("shatter: %w", err)
		}
		if !isTrackedJump(entry) {
			continue
		}
		if entry.target >= 0 && entry.target < int64(len(p.text.Data)) {
			if _, ok := p.boundaries[uint32(entry.target)]; ok {
				targets[uint32(entry.target)] = struct{}{}
			}
		}
	}
	for _, function := range p.functions {
		var current *block
		leader := func(entry *instruction) {
			if current != nil {
				target := entry.oldStart
				current.edgeTarget = &target
			}
			current = &block{region: function, start: entry.oldStart, entries: []*instruction{entry}}
			function.blocks = append(function.blocks, current)
		}
		add := func(entry *instruction) { current.entries = append(current.entries, entry) }
		for index := 0; index < len(function.instructions); index++ {
			entry := function.instructions[index]
			_, jumpTarget := targets[entry.oldStart]
			if current == nil || jumpTarget {
				leader(entry)
			} else {
				add(entry)
			}
			// This loop is intentionally shaped like upstream Blocks.BlockGroup:
			// a chain of jump/exit instructions repeatedly consumes the following
			// instruction as a leader before the outer iterator resumes.
			for (isTrackedJump(entry) || isFunctionExit(entry, p.object.Machine)) && index+1 < len(function.instructions) {
				index++
				entry = function.instructions[index]
				leader(entry)
			}
		}
		p.report.Functions++
		p.report.OriginalBlocks += len(function.blocks)
	}
	return nil
}

func (p *plan) distributeBlocks(ctx context.Context, random boundedRandom) error {
	ordered, err := javaHashOrder(p.functions)
	if err != nil {
		return err
	}
	var rest []*block
	for _, function := range ordered {
		if len(function.blocks) == 0 {
			return fmt.Errorf("shatter: function %q has no basic block", function.name)
		}
		function.physical = []*block{function.blocks[0]}
		rest = append(rest, function.blocks[1:]...)
	}
	draws, err := shuffleBlocks(rest, random)
	p.report.RandomDraws += draws
	if err != nil {
		return fmt.Errorf("shatter: shuffle blocks: %w", err)
	}
	p.report.ShuffledBlocks = len(rest)
	for index, next := range rest {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("shatter: %w", err)
		}
		if len(ordered) == 0 {
			return errors.New("shatter: shuffled blocks exist without a function home")
		}
		home := ordered[index%len(ordered)]
		home.physical = append(home.physical, next)
		assignment := BlockAssignment{SourceFunction: next.region.name, HomeFunction: home.name, Start: next.start}
		p.report.Assignments = append(p.report.Assignments, assignment)
	}
	for _, function := range p.functions {
		layout := FunctionLayout{Name: function.name}
		for _, next := range function.physical {
			layout.Blocks = append(layout.Blocks, BlockAssignment{
				SourceFunction: next.region.name,
				HomeFunction:   function.name,
				Start:          next.start,
			})
		}
		p.report.Layouts = append(p.report.Layouts, layout)
	}
	return nil
}

func (p *plan) buildFragments(ctx context.Context) error {
	for _, current := range p.regions {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("shatter: %w", err)
		}
		if !current.isFunction {
			for _, entry := range current.instructions {
				p.appendInstructionFragment(current, entry, nil)
			}
			continue
		}
		var entries []*instruction
		edges := make(map[*instruction]uint32)
		for _, next := range current.physical {
			entries = append(entries, next.entries...)
			if next.edgeTarget != nil && len(next.entries) != 0 {
				edges[next.entries[len(next.entries)-1]] = *next.edgeTarget
			}
		}
		for index, entry := range entries {
			var following *instruction
			if index+1 < len(entries) {
				following = entries[index+1]
			}
			p.appendInstructionFragment(current, entry, following)
			if target, edge := edges[entry]; edge && !isUnconditionalJump(entry) {
				if following == nil || following.oldStart != target {
					connector := fragmentForConnector(current, target)
					p.fragments = append(p.fragments, &connector)
					p.report.Connectors++
				}
			}
		}
	}
	return nil
}

func (p *plan) appendInstructionFragment(home *region, entry, following *instruction) *fragment {
	output := append([]byte(nil), entry.raw...)
	fragment := &fragment{entry: entry, output: output, region: home}
	if len(entry.relocations) == 0 && entry.hasRelative {
		switch entry.relative.kind {
		case relativeJump:
			// Iced's BlockEncoder selects the short JMP form whenever it fits,
			// both for Jumps.process and LocalLabels' CodeAssembler.jmp().
			fragment.output = []byte{0xeb, 0}
			if p.labels[uint32(entry.target)] == nil && following != nil && entry.target == int64(following.oldStart) {
				// Jumps.process() heals a direct JMP only when the following
				// original instruction owns the same target label.
				fragment.output = nil
				fragment.removed = true
				p.report.HealedJumps++
			}
		case relativeConditional:
			condition := byte(0)
			if entry.relative.size == 1 {
				condition = entry.raw[0] & 0x0f
			} else {
				condition = entry.raw[1] & 0x0f
			}
			fragment.output = []byte{0x70 | condition, 0}
		}
	}
	p.fragments = append(p.fragments, fragment)
	p.byEntry[entry] = fragment
	return fragment
}

func fragmentForConnector(home *region, target uint32) fragment {
	return fragment{connector: true, target: target, output: []byte{0xeb, 0}, region: home}
}

func isTrackedJump(entry *instruction) bool {
	return entry != nil && entry.hasRelative && (entry.relative.kind == relativeJump || entry.relative.kind == relativeConditional || entry.relative.kind == relativeLoop)
}

func isUnconditionalJump(entry *instruction) bool {
	if entry == nil || entry.mnemonic != "jmp" {
		return false
	}
	if entry.hasRelative && entry.relative.kind == relativeJump {
		return true
	}
	position := skipPrefixes(entry.raw)
	if position+2 > len(entry.raw) || entry.raw[position] != 0xff {
		return false
	}
	return (entry.raw[position+1]>>3)&7 == 4
}

func isFunctionExit(entry *instruction, machine coff.Machine) bool {
	if entry == nil {
		return false
	}
	position := skipPrefixes(entry.raw)
	if entry.mnemonic == "ret" && position+1 == len(entry.raw) && entry.raw[position] == 0xc3 {
		return true
	}
	if machine != coff.MachineAMD64 || entry.mnemonic != "jmp" || strings.TrimSpace(entry.operands) != "rcx" {
		return false
	}
	if position+2 != len(entry.raw) || entry.raw[position] != 0xff {
		return false
	}
	modrm := entry.raw[position+1]
	return modrm>>6 == 3 && (modrm>>3)&7 == 4 && modrm&7 == 1
}
