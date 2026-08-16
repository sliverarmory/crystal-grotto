// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package intrinsicexpand

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
	"github.com/sliverarmory/crystal-grotto/internal/ised"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var applyMu sync.Mutex

type plannedSite struct {
	function        string
	symbol          string
	kind            hooks.ExpansionKind
	offset          uint32
	instruction     ised.Instruction
	replacement     []byte
	relocationIndex int
}

// Apply expands every canonical user intrinsic and named-hash/tag intrinsic in
// one rebuild, matching upstream's MultiModify intrinsic pass. The source
// object and hook model are never mutated.
func Apply(ctx context.Context, object *coff.Object, model *hooks.Model, options Options) (*coff.Object, Report, error) {
	if ctx == nil {
		return nil, Report{}, fmt.Errorf("%w: nil context", ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return nil, Report{}, fmt.Errorf("intrinsicexpand: %w", err)
	}
	if object == nil || model == nil {
		return nil, Report{}, fmt.Errorf("%w: nil object or hook model", ErrInvalidInput)
	}
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return nil, Report{}, fmt.Errorf("%w: unsupported machine %s", ErrInvalidInput, object.Machine)
	}
	if model.Machine() != object.Machine {
		return nil, Report{}, fmt.Errorf("%w: hook model machine %s differs from object machine %s", ErrInvalidInput, model.Machine(), object.Machine)
	}
	if options.Disassembler != nil && options.NewDisassembler != nil {
		return nil, Report{}, fmt.Errorf("%w: Disassembler and NewDisassembler are mutually exclusive", ErrInvalidInput)
	}

	applyMu.Lock()
	defer applyMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, Report{}, fmt.Errorf("intrinsicexpand: %w", err)
	}

	text := object.GetSection(".text")
	if text == nil {
		return nil, Report{}, fmt.Errorf("%w: object has no .text section", ErrInvalidModel)
	}
	needsLift := false
	for _, relocation := range text.Relocations {
		if relocation == nil {
			return nil, Report{}, fmt.Errorf("%w: .text contains a nil relocation", ErrInvalidModel)
		}
		name, err := relocationName(relocation)
		if err != nil {
			return nil, Report{}, err
		}
		if intrinsicCandidate(model, name) {
			needsLift = true
			break
		}
	}
	if !needsLift {
		candidate, err := cloneObject(object)
		if err != nil {
			return nil, Report{}, fmt.Errorf("%w: clone input: %v", ErrInvalidModel, err)
		}
		if err := ctx.Err(); err != nil {
			return nil, Report{}, fmt.Errorf("intrinsicexpand: %w", err)
		}
		return candidate, Report{}, nil
	}

	if err := validateCodeSymbols(object, text); err != nil {
		return nil, Report{}, err
	}
	unwindAware := object.Machine == coff.MachineAMD64
	program, err := ised.LiftObject(ctx, object, ised.ObjectOptions{
		Unwind:       unwindAware,
		Disassembler: options.Disassembler, NewDisassembler: options.NewDisassembler,
	})
	if err != nil {
		if errors.Is(err, ised.ErrInvalidObject) {
			return nil, Report{}, fmt.Errorf("%w: lift object: %w", ErrInvalidModel, err)
		}
		return nil, Report{}, fmt.Errorf("intrinsicexpand: lift object: %w", err)
	}
	planned, err := planSites(ctx, object, model, program)
	if err != nil {
		return nil, Report{}, err
	}
	if len(planned) == 0 {
		candidate, err := cloneObject(object)
		if err != nil {
			return nil, Report{}, fmt.Errorf("%w: clone input: %v", ErrInvalidModel, err)
		}
		if err := ctx.Err(); err != nil {
			return nil, Report{}, fmt.Errorf("intrinsicexpand: %w", err)
		}
		return candidate, Report{}, nil
	}

	candidate, err := cloneObject(object)
	if err != nil {
		return nil, Report{}, fmt.Errorf("%w: clone input: %v", ErrInvalidModel, err)
	}
	candidateText := candidate.GetSection(".text")
	remove := make(map[int]struct{}, len(planned))
	plan := ised.Plan{Machine: candidate.Machine, Unwind: unwindAware, Edits: make([]ised.Edit, 0, len(planned))}
	report := Report{Sites: make([]Site, 0, len(planned))}
	for _, site := range planned {
		remove[site.relocationIndex] = struct{}{}
		plan.Edits = append(plan.Edits, ised.Edit{
			Function: site.function, Section: candidateText.Name, Original: site.instruction,
			Replace: &ised.Selection{CommandIndex: -1, Content: append([]byte(nil), site.replacement...)},
		})
		if site.kind == hooks.ExpansionUserBytes {
			report.Sites = append(report.Sites, Site{
				Function: site.function, Symbol: site.symbol, Offset: site.offset,
				OriginalLen: len(site.instruction.Bytes), ResultLen: len(site.replacement),
			})
			report.BytesDelta += int64(len(site.replacement) - len(site.instruction.Bytes))
		}
	}
	kept := make([]*coff.Relocation, 0, len(candidateText.Relocations)-len(remove))
	for index, relocation := range candidateText.Relocations {
		if _, consumed := remove[index]; !consumed {
			kept = append(kept, relocation)
		}
	}
	candidateText.Relocations = kept
	if err := (ised.RebaseBackend{Context: ctx}).RewriteISED(candidate, program, plan); err != nil {
		if errors.Is(err, ised.ErrInvalidObject) || errors.Is(err, ised.ErrInvalidProgram) {
			return nil, Report{}, fmt.Errorf("%w: rebuild: %w", ErrInvalidModel, err)
		}
		return nil, Report{}, fmt.Errorf("intrinsicexpand: rebuild: %w", err)
	}
	removeConsumedUndefinedSymbols(candidate, planned)
	validated, err := cloneObject(candidate)
	if err != nil {
		return nil, Report{}, fmt.Errorf("%w: validate output: %v", ErrInvalidModel, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, Report{}, fmt.Errorf("intrinsicexpand: %w", err)
	}
	return validated, cloneReport(report), nil
}

func removeConsumedUndefinedSymbols(object *coff.Object, sites []plannedSite) {
	consumed := make(map[string]struct{}, len(sites))
	for _, site := range sites {
		consumed[site.symbol] = struct{}{}
	}
	for _, section := range object.Sections {
		if section == nil {
			continue
		}
		for _, relocation := range section.Relocations {
			if relocation == nil {
				continue
			}
			name := relocation.SymbolName
			if name == "" && relocation.Symbol != nil {
				name = relocation.Symbol.Name
			}
			delete(consumed, name)
		}
	}
	remove := make(map[string]struct{}, len(consumed))
	for name := range consumed {
		if symbol := object.GetSymbol(name); symbol != nil && symbol.IsUndefined() {
			// ProgramCOFF omits unreferenced undefined symbols. Doing the same
			// here also prevents later fixed-size hook planning from needlessly
			// decoding arbitrary intrinsic bytes solely because the stale symbol
			// remains in the in-memory table.
			remove[name] = struct{}{}
		}
	}
	object.RemoveSymbols(remove)
}

func planSites(ctx context.Context, object *coff.Object, model *hooks.Model, program ised.Program) ([]plannedSite, error) {
	text := object.GetSection(".text")
	wantType := uint16(coff.RelAMD64Rel32)
	if object.Machine == coff.MachineI386 {
		wantType = coff.RelI386Rel32
	}
	var result []plannedSite
	for relocationIndex, relocation := range text.Relocations {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("intrinsicexpand: %w", err)
		}
		name, err := relocationName(relocation)
		if err != nil {
			return nil, err
		}
		if !intrinsicCandidate(model, name) {
			continue
		}
		if symbol := codeSymbolAt(object, text, relocation.VirtualAddress); symbol != nil && !symbol.IsFunction() {
			// Rebuilder copies global-data groups byte-for-byte without running
			// its AddInstruction passes.
			continue
		}
		function, instruction, found := containingInstruction(program, relocation.VirtualAddress)
		fail := func(err error) error {
			return &SiteError{Function: function, Symbol: name, Offset: relocation.VirtualAddress, Err: err}
		}
		if !found {
			return nil, fail(fmt.Errorf("%w: relocation is outside a lifted function instruction", ErrUnsupportedForm))
		}
		expansion, matched, err := model.ResolveIntrinsic(hooks.CallSite{
			HasRelocation: true, Symbol: name,
			Instruction: x86.Instruction{Bytes: append([]byte(nil), instruction.Bytes...), Form: instruction.Form},
		})
		if err != nil {
			return nil, fail(fmt.Errorf("%w: %v", ErrUnsupportedForm, err))
		}
		if !matched || expansion.Kind != hooks.ExpansionUserBytes && expansion.Kind != hooks.ExpansionHashImmediate {
			continue
		}
		if relocation.Type != wantType || instruction.Form != "CALL rel32" || instruction.RelativeWidth != 4 || relocation.VirtualAddress != instruction.Offset+uint32(instruction.RelativeOffset) {
			return nil, fail(fmt.Errorf("%w: intrinsic requires CALL rel32 with a matching REL32 relocation", ErrUnsupportedForm))
		}
		end := uint64(instruction.Offset) + uint64(len(instruction.Bytes))
		for otherIndex, other := range text.Relocations {
			if otherIndex == relocationIndex || other == nil {
				continue
			}
			if uint64(other.VirtualAddress) >= uint64(instruction.Offset) && uint64(other.VirtualAddress) < end {
				return nil, fail(fmt.Errorf("%w: intrinsic instruction has multiple relocations", ErrUnsupportedForm))
			}
		}
		result = append(result, plannedSite{
			function: function, symbol: name, kind: expansion.Kind, offset: instruction.Offset,
			instruction: instruction, replacement: append([]byte(nil), expansion.Bytes...),
			relocationIndex: relocationIndex,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].offset < result[j].offset })
	for index := 1; index < len(result); index++ {
		previousEnd := uint64(result[index-1].offset) + uint64(len(result[index-1].instruction.Bytes))
		if uint64(result[index].offset) < previousEnd || previousEnd > math.MaxUint32 {
			return nil, fmt.Errorf("%w: overlapping intrinsic sites", ErrInvalidModel)
		}
	}
	return result, nil
}

func intrinsicCandidate(model *hooks.Model, symbol string) bool {
	expansion, matched, err := model.ResolveIntrinsic(hooks.CallSite{
		HasRelocation: true,
		Symbol:        symbol,
		Instruction:   x86.Instruction{Bytes: []byte{0xe8, 0, 0, 0, 0}, Form: "CALL rel32"},
	})
	return err == nil && matched && (expansion.Kind == hooks.ExpansionUserBytes || expansion.Kind == hooks.ExpansionHashImmediate)
}

func relocationName(relocation *coff.Relocation) (string, error) {
	if relocation == nil {
		return "", fmt.Errorf("%w: nil relocation", ErrInvalidModel)
	}
	if relocation.Symbol != nil {
		if relocation.Symbol.Name == "" {
			return "", fmt.Errorf("%w: relocation points to an unnamed symbol", ErrInvalidModel)
		}
		if relocation.SymbolName != "" && relocation.SymbolName != relocation.Symbol.Name {
			return "", fmt.Errorf("%w: relocation names symbol %q but points to %q", ErrInvalidModel, relocation.SymbolName, relocation.Symbol.Name)
		}
		return relocation.Symbol.Name, nil
	}
	if relocation.SymbolName == "" {
		return "", fmt.Errorf("%w: relocation has no symbol", ErrInvalidModel)
	}
	return relocation.SymbolName, nil
}

func validateCodeSymbols(object *coff.Object, text *coff.Section) error {
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return fmt.Errorf("%w: symbol %d is nil", ErrInvalidModel, index)
		}
		if symbol.Section != text || symbol.IsFunction() || symbol.IsGlobalVariable() {
			continue
		}
		// Code.analyze rejects these ambiguous non-function code symbols before
		// Rebuilder runs any intrinsic pass.
		if symbol.Type == 0 && symbol.Value > 0 {
			return fmt.Errorf("%w: candidate .text symbol %q at %#x is neither a function nor global data", ErrInvalidModel, symbol.Name, symbol.Value)
		}
	}
	return nil
}

func codeSymbolAt(object *coff.Object, text *coff.Section, offset uint32) *coff.Symbol {
	var current *coff.Symbol
	for _, symbol := range object.Symbols {
		if symbol == nil || symbol.Section != text || !symbol.IsFunction() && !symbol.IsGlobalVariable() || symbol.Value > offset {
			continue
		}
		if current == nil || symbol.Value >= current.Value {
			// Code.analyze stores labels in a value-keyed map, so later aliases
			// at one address win.
			current = symbol
		}
	}
	return current
}

func containingInstruction(program ised.Program, relocation uint32) (string, ised.Instruction, bool) {
	for _, function := range program.Functions {
		for _, instruction := range function.Instructions {
			end := uint64(instruction.Offset) + uint64(len(instruction.Bytes))
			if uint64(relocation) >= uint64(instruction.Offset) && uint64(relocation)+4 <= end {
				instruction.Bytes = append([]byte(nil), instruction.Bytes...)
				return function.Name, instruction, true
			}
		}
	}
	return "", ised.Instruction{}, false
}

func cloneObject(object *coff.Object) (*coff.Object, error) {
	encoded, err := coffwrite.Marshal(object)
	if err != nil {
		return nil, err
	}
	return coff.Parse(encoded)
}

func cloneReport(report Report) Report {
	report.Sites = append([]Site(nil), report.Sites...)
	return report
}
