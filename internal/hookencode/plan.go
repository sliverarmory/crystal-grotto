// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package hookencode

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

type relocationRef struct {
	index       int
	relocation  *coff.Relocation
	instruction int
}

type analysis struct {
	sectionIndex  int
	section       *coff.Section
	instructions  []x86.Instruction
	contexts      []string
	labels        map[uint32]*coff.Symbol
	refs          []relocationRef
	byInstruction map[int][]relocationRef
}

// BuildPlan analyzes the object's .text section without mutating either the
// object or model. It returns every supported rewrite in Crystal Palace pass
// order: intrinsics, redirects, attaches.
func BuildPlan(ctx context.Context, object *coff.Object, model *hooks.Model) (Plan, error) {
	if ctx == nil {
		return Plan{}, ErrNilContext
	}
	if object == nil {
		return Plan{}, ErrNilObject
	}
	if model == nil {
		return Plan{}, ErrNilModel
	}
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return Plan{}, fmt.Errorf("%w: %s", ErrUnsupportedMachine, object.Machine)
	}
	if model.Machine() != object.Machine {
		return Plan{}, fmt.Errorf("hookencode: model machine %s differs from object machine %s", model.Machine(), object.Machine)
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, fmt.Errorf("hookencode: build plan: %w", err)
	}

	plan := Plan{Machine: object.Machine}
	if !needsAnalysis(object, model) {
		return plan, nil
	}
	state, err := analyzeText(ctx, object)
	if err != nil {
		return Plan{}, err
	}
	processed := make(map[*coff.Relocation]struct{})

	if err := planIntrinsics(ctx, object, model, state, &plan, processed); err != nil {
		return Plan{}, err
	}
	if err := planRedirects(ctx, object, model, state, &plan, processed); err != nil {
		return Plan{}, err
	}
	if err := planAttaches(ctx, object, model, state, &plan, processed); err != nil {
		return Plan{}, err
	}
	if err := validatePlannedSites(plan); err != nil {
		return Plan{}, err
	}
	return clonePlan(plan), nil
}

func validatePlannedSites(plan Plan) error {
	spans := make(map[int][][2]uint32)
	relocations := make(map[[2]int]struct{})
	for _, site := range plan.Sites {
		end64 := uint64(site.InstructionOffset) + uint64(site.InstructionLength)
		if site.InstructionLength == 0 || end64 > math.MaxUint32 {
			return &SiteError{Pass: site.Pass, Section: site.SectionName, Relocation: site.RelocationIndex, Offset: site.InstructionOffset, Symbol: site.Symbol, Err: fmt.Errorf("%w: invalid instruction span", ErrInvalidPlan)}
		}
		end := uint32(end64)
		for _, previous := range spans[site.SectionIndex] {
			if site.InstructionOffset < previous[1] && previous[0] < end {
				return &SiteError{Pass: site.Pass, Section: site.SectionName, Relocation: site.RelocationIndex, Offset: site.InstructionOffset, Symbol: site.Symbol, Err: fmt.Errorf("%w: planned instruction overlaps another rewrite", ErrInvalidPlan)}
			}
		}
		spans[site.SectionIndex] = append(spans[site.SectionIndex], [2]uint32{site.InstructionOffset, end})
		if site.RelocationIndex >= 0 {
			key := [2]int{site.SectionIndex, site.RelocationIndex}
			if _, duplicate := relocations[key]; duplicate {
				return &SiteError{Pass: site.Pass, Section: site.SectionName, Relocation: site.RelocationIndex, Offset: site.RelocationOffset, Symbol: site.Symbol, Err: fmt.Errorf("%w: relocation is planned more than once", ErrInvalidPlan)}
			}
			relocations[key] = struct{}{}
		}
	}
	return nil
}

func needsAnalysis(object *coff.Object, model *hooks.Model) bool {
	if model.HasExternalHooks() || model.HasLocalHooks() {
		return true
	}
	call := x86.Instruction{Bytes: []byte{0xe8, 0, 0, 0, 0}, Form: "CALL rel32"}
	for _, symbol := range object.Symbols {
		if symbol == nil {
			continue
		}
		_, matched, err := model.ResolveIntrinsic(hooks.CallSite{
			HasRelocation: true, Symbol: symbol.Name, Instruction: call,
		})
		if matched || err != nil {
			return true
		}
	}
	return false
}

func analyzeText(ctx context.Context, object *coff.Object) (*analysis, error) {
	section := object.GetSection(".text")
	if section == nil {
		return nil, errors.New("hookencode: active hook pass requires a .text section")
	}
	sectionIndex := -1
	for index, candidate := range object.Sections {
		if candidate == section {
			sectionIndex = index
			break
		}
	}
	if sectionIndex < 0 {
		return nil, errors.New("hookencode: .text section is not in object section order")
	}
	mode := x86.Mode64
	if object.Machine == coff.MachineI386 {
		mode = x86.Mode32
	}
	disassembler, err := x86.NewCapstone(ctx, mode)
	if err != nil {
		return nil, fmt.Errorf("hookencode: open %s decoder: %w", object.Machine, err)
	}
	instructions, decodeErr := disassembler.Disassemble(ctx, section.Data, 0)
	closeErr := disassembler.Close(context.Background())
	if decodeErr != nil {
		return nil, fmt.Errorf("hookencode: decode .text: %w", decodeErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("hookencode: close .text decoder: %w", closeErr)
	}

	state := &analysis{
		sectionIndex:  sectionIndex,
		section:       section,
		instructions:  instructions,
		labels:        make(map[uint32]*coff.Symbol),
		byInstruction: make(map[int][]relocationRef),
	}
	for _, symbol := range object.Symbols {
		if symbol == nil || symbol.Section != section {
			continue
		}
		if symbol.IsFunction() || symbol.IsGlobalVariable() {
			// Code.analyze uses a value-keyed map and later entries replace
			// earlier aliases at the same address.
			state.labels[symbol.Value] = symbol
		}
	}
	state.contexts = make([]string, len(instructions))
	contextName := ""
	for index, instruction := range instructions {
		if instruction.Address > math.MaxUint32 {
			return nil, errors.New("hookencode: decoded .text address exceeds COFF range")
		}
		if label := state.labels[uint32(instruction.Address)]; label != nil {
			contextName = ""
			if label.IsFunction() {
				contextName = label.Name
			}
		}
		state.contexts[index] = contextName
	}

	for index, relocation := range section.Relocations {
		if relocation == nil {
			return nil, &SiteError{Pass: PassIntrinsic, Section: section.Name, Relocation: index, Err: errors.New("nil relocation")}
		}
		instructionIndex := instructionForRelocation(instructions, relocation.VirtualAddress)
		entry := relocationRef{index: index, relocation: relocation, instruction: instructionIndex}
		state.refs = append(state.refs, entry)
		if instructionIndex >= 0 {
			state.byInstruction[instructionIndex] = append(state.byInstruction[instructionIndex], entry)
		}
	}
	sort.SliceStable(state.refs, func(i, j int) bool {
		if state.refs[i].relocation.VirtualAddress != state.refs[j].relocation.VirtualAddress {
			return state.refs[i].relocation.VirtualAddress < state.refs[j].relocation.VirtualAddress
		}
		return state.refs[i].index < state.refs[j].index
	})
	return state, nil
}

func instructionForRelocation(instructions []x86.Instruction, address uint32) int {
	for index, instruction := range instructions {
		start := instruction.Address
		end := start + uint64(len(instruction.Bytes))
		if uint64(address) >= start && uint64(address)+4 <= end {
			return index
		}
	}
	return -1
}

func planIntrinsics(ctx context.Context, object *coff.Object, model *hooks.Model, state *analysis, plan *Plan, processed map[*coff.Relocation]struct{}) error {
	for _, ref := range state.refs {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("hookencode: plan intrinsics: %w", err)
		}
		call := x86.Instruction{}
		contextName := ""
		if ref.instruction >= 0 {
			call = cloneInstruction(state.instructions[ref.instruction])
			contextName = state.contexts[ref.instruction]
			if relativeOffset, offsetErr := instructionRelativeOffset(call, ref.relocation.VirtualAddress); offsetErr == nil && isCallRel32(call.Bytes, relativeOffset) {
				call.Form = "CALL rel32"
			}
		}
		expansion, matched, resolveErr := model.ResolveIntrinsic(hooks.CallSite{
			HasRelocation: true,
			Symbol:        ref.relocation.SymbolName,
			Instruction:   call,
		})
		if !matched && resolveErr == nil {
			continue
		}
		fail := func(err error) error {
			return siteError(PassIntrinsic, state, ref, err)
		}
		if contextName == "" {
			// Upstream rebuilds only instruction groups rooted at a function.
			continue
		}
		if ref.instruction < 0 {
			return fail(fmt.Errorf("%w: relocation is not contained by one decoded instruction", ErrUnsupportedForm))
		}
		if resolveErr != nil {
			return fail(fmt.Errorf("%w: %v", ErrUnsupportedForm, resolveErr))
		}
		if expansion.Kind == hooks.ExpansionResolveHooks || expansion.RequiresEncoder {
			return fail(fmt.Errorf("%w: %w", ErrResolveHook, hooks.ErrEncoderRequired))
		}
		instruction := state.instructions[ref.instruction]
		relativeOffset := int(ref.relocation.VirtualAddress) - int(instruction.Address)
		if !isCallRel32(instruction.Bytes, relativeOffset) || !isRelativeType(object.Machine, ref.relocation.Type) {
			return fail(fmt.Errorf("%w: intrinsic requires CALL rel32 with a matching REL32 relocation", ErrUnsupportedForm))
		}
		if expansion.RequiresRebuild || len(expansion.Bytes) != len(instruction.Bytes) {
			return fail(fmt.Errorf("%w: %s expands %d bytes to %d", ErrRebuildRequired, ref.relocation.SymbolName, len(instruction.Bytes), len(expansion.Bytes)))
		}
		plan.Sites = append(plan.Sites, Site{
			Pass: PassIntrinsic, Form: FormCallRel32,
			SectionIndex: state.sectionIndex, RelocationIndex: ref.index,
			SectionName: state.section.Name, RelocationOffset: ref.relocation.VirtualAddress,
			InstructionOffset: uint32(instruction.Address), InstructionLength: uint32(len(instruction.Bytes)),
			Context: contextName, Target: ref.relocation.SymbolName, Symbol: ref.relocation.SymbolName,
			Original: append([]byte(nil), instruction.Bytes...), Replacement: append([]byte(nil), expansion.Bytes...),
			action: relocationConsume, originalType: ref.relocation.Type, originalSymbol: ref.relocation.SymbolName,
		})
		processed[ref.relocation] = struct{}{}
	}
	return nil
}

func planRedirects(ctx context.Context, object *coff.Object, model *hooks.Model, state *analysis, plan *Plan, processed map[*coff.Relocation]struct{}) error {
	if !model.HasLocalHooks() {
		return nil
	}
	firstSite := len(plan.Sites)
	// Crystal Palace first handles relocation-bearing x86 address loads. We
	// additionally keep canonical pre-merge local REL32 forms relocatable; the
	// post-merge resolved forms below are the ordinary upstream path.
	for _, ref := range state.refs {
		if _, done := processed[ref.relocation]; done {
			continue
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("hookencode: plan redirects: %w", err)
		}
		if ref.instruction < 0 {
			continue
		}
		contextName := state.contexts[ref.instruction]
		if contextName == "" {
			continue
		}
		targetSymbol := relocationLocalTarget(object.Machine, state, ref.relocation)
		if targetSymbol == nil {
			continue
		}
		route := model.PlanRedirect(contextName, targetSymbol.Name)
		if !route.Matched {
			continue
		}
		wrapper, err := validateWrapper(object, state.section, route.Wrapper)
		if err != nil {
			return siteError(PassRedirect, state, ref, err)
		}
		instruction := state.instructions[ref.instruction]
		site, err := encodeRelocatedRedirect(object, state, ref, instruction, contextName, targetSymbol.Name, wrapper)
		if err != nil {
			return siteError(PassRedirect, state, ref, err)
		}
		plan.Sites = append(plan.Sites, site)
		processed[ref.relocation] = struct{}{}
	}

	for instructionIndex, instruction := range state.instructions {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("hookencode: plan redirects: %w", err)
		}
		if len(state.byInstruction[instructionIndex]) != 0 || state.contexts[instructionIndex] == "" {
			continue
		}
		form, target, operandOffset, operandWidth, recognized := classifyResolvedLocal(object.Machine, instruction)
		if !recognized || target < 0 || target > int64(len(state.section.Data)) {
			continue
		}
		targetSymbol := state.labels[uint32(target)]
		if targetSymbol == nil {
			continue
		}
		contextName := state.contexts[instructionIndex]
		route := model.PlanRedirect(contextName, targetSymbol.Name)
		if !route.Matched {
			continue
		}
		wrapper, err := validateWrapper(object, state.section, route.Wrapper)
		if err != nil {
			return instructionSiteError(PassRedirect, state, instruction, err)
		}
		replacement, err := retargetRelative(instruction.Bytes, operandOffset, operandWidth, instruction.Address, wrapper.Value)
		if err != nil {
			return instructionSiteError(PassRedirect, state, instruction, err)
		}
		plan.Sites = append(plan.Sites, Site{
			Pass: PassRedirect, Form: form,
			SectionIndex: state.sectionIndex, RelocationIndex: -1,
			SectionName:       state.section.Name,
			InstructionOffset: uint32(instruction.Address), InstructionLength: uint32(len(instruction.Bytes)),
			Context: contextName, Target: targetSymbol.Name, Wrapper: wrapper.Name,
			Original: append([]byte(nil), instruction.Bytes...), Replacement: replacement,
		})
	}
	sort.SliceStable(plan.Sites[firstSite:], func(i, j int) bool {
		left, right := plan.Sites[firstSite+i], plan.Sites[firstSite+j]
		if left.InstructionOffset != right.InstructionOffset {
			return left.InstructionOffset < right.InstructionOffset
		}
		return left.RelocationIndex < right.RelocationIndex
	})
	return nil
}

func planAttaches(ctx context.Context, object *coff.Object, model *hooks.Model, state *analysis, plan *Plan, processed map[*coff.Relocation]struct{}) error {
	if !model.HasExternalHooks() {
		return nil
	}
	for _, ref := range state.refs {
		if _, done := processed[ref.relocation]; done {
			continue
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("hookencode: plan attaches: %w", err)
		}
		contextName := ""
		if ref.instruction >= 0 {
			contextName = state.contexts[ref.instruction]
		}
		if contextName == "" {
			continue
		}
		route := model.PlanAttachImport(contextName, ref.relocation.SymbolName)
		if !route.Matched {
			continue
		}
		if ref.instruction < 0 {
			return siteError(PassAttach, state, ref, fmt.Errorf("%w: relocation is not contained by one decoded instruction", ErrUnsupportedForm))
		}
		wrapper, err := validateWrapper(object, state.section, route.Wrapper)
		if err != nil {
			return siteError(PassAttach, state, ref, err)
		}
		site, err := encodeAttach(object, state, ref, state.instructions[ref.instruction], contextName, route.Target, wrapper)
		if err != nil {
			return siteError(PassAttach, state, ref, err)
		}
		plan.Sites = append(plan.Sites, site)
		processed[ref.relocation] = struct{}{}
	}
	return nil
}

func cloneInstruction(instruction x86.Instruction) x86.Instruction {
	result := instruction
	result.Bytes = append([]byte(nil), instruction.Bytes...)
	if instruction.Detail != nil {
		detail := *instruction.Detail
		result.Detail = &detail
	}
	return result
}

func isCallRel32(bytes []byte, relocationOffset int) bool {
	return len(bytes) == 5 && bytes[0] == 0xe8 && relocationOffset == 1
}

func isRelativeType(machine coff.Machine, relocationType uint16) bool {
	if machine == coff.MachineAMD64 {
		return relocationType == coff.RelAMD64Rel32
	}
	return machine == coff.MachineI386 && relocationType == coff.RelI386Rel32
}

func validateWrapper(object *coff.Object, text *coff.Section, name string) (*coff.Symbol, error) {
	wrapper := object.GetSymbol(name)
	if wrapper == nil {
		return nil, fmt.Errorf("hook wrapper %q no longer exists", name)
	}
	if !wrapper.IsFunction() || wrapper.Section != text {
		return nil, fmt.Errorf("hook wrapper %q is not a function in .text", name)
	}
	if uint64(wrapper.Value) >= uint64(len(text.Data)) && len(text.Data) != 0 {
		return nil, fmt.Errorf("hook wrapper %q lies outside .text", name)
	}
	return wrapper, nil
}

func relocationLocalTarget(machine coff.Machine, state *analysis, relocation *coff.Relocation) *coff.Symbol {
	if relocation == nil || relocation.Symbol == nil || relocation.Symbol.Section != state.section {
		return nil
	}
	if uint64(relocation.VirtualAddress)+4 > uint64(len(state.section.Data)) {
		return nil
	}
	var target int64
	if isRelativeType(machine, relocation.Type) {
		addend := int64(int32(binary.LittleEndian.Uint32(state.section.Data[relocation.VirtualAddress : relocation.VirtualAddress+4])))
		target = int64(relocation.Symbol.Value) + addend
	} else if machine == coff.MachineI386 && relocation.Type == coff.RelI386Dir32 {
		addend := uint64(binary.LittleEndian.Uint32(state.section.Data[relocation.VirtualAddress : relocation.VirtualAddress+4]))
		total := uint64(relocation.Symbol.Value) + addend
		if total > math.MaxUint32 {
			return nil
		}
		target = int64(total)
	} else {
		return nil
	}
	if target < 0 || target > math.MaxUint32 {
		return nil
	}
	return state.labels[uint32(target)]
}

func siteError(pass Pass, state *analysis, ref relocationRef, err error) error {
	return &SiteError{
		Pass: pass, Section: state.section.Name, Relocation: ref.index,
		Offset: ref.relocation.VirtualAddress, Symbol: ref.relocation.SymbolName, Err: err,
	}
}

func instructionSiteError(pass Pass, state *analysis, instruction x86.Instruction, err error) error {
	return &SiteError{
		Pass: pass, Section: state.section.Name, Relocation: -1,
		Offset: uint32(instruction.Address), Err: err,
	}
}
