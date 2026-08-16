// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package rulegen

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/spec"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var (
	ErrNilContext         = errors.New("rulegen: nil context")
	ErrNilObject          = errors.New("rulegen: nil COFF object")
	ErrUnsupportedMachine = errors.New("rulegen: unsupported machine")
	ErrMalformedObject    = errors.New("rulegen: malformed COFF object")
)

// DisassemblerFactory opens one decoder for a generation operation.
type DisassemblerFactory func(context.Context, x86.Mode) (x86.Disassembler, error)

// UUIDSource supplies the UUID string used in the generated rule name.
type UUIDSource func() (string, error)

// GenerateOptions injects platform services. Zero values use Capstone,
// crypto/rand, UUIDv4 formatting, and time.Now.
type GenerateOptions struct {
	NewDisassembler DisassemblerFactory
	UUID            UUIDSource
	Random          io.Reader
	Clock           func() time.Time
}

// Warning explains a conservative omission or a non-fatal selection result.
type Warning struct {
	Code     string
	Function string
	Offset   uint32
	Message  string
}

const (
	WarningBoundaryDetail = "boundary-detail-unavailable"
	WarningControlFlow    = "control-flow-detail-unavailable"
	WarningNoRules        = "no-rules"
	WarningTargetMissing  = "target-function-missing"
)

// FunctionResult summarizes candidate disposition for one function.
type FunctionResult struct {
	Name       string
	Candidates int
	Selected   int
	Omitted    int
}

// Result contains generated YARA and deterministic selection diagnostics.
type Result struct {
	YARA              []byte
	RuleName          string
	RuleCount         int
	CandidateCount    int
	OmittedCandidates int
	Warnings          []Warning
	Functions         []FunctionResult
}

type functionRange struct {
	name    string
	section *coff.Section
	start   uint32
	end     uint32
}

type candidate struct {
	functionIndex int
	blockIndex    int
	rule          Rule
}

type flowInfo struct {
	boundaryAfter bool
	exit          bool
	target        uint64
	hasTarget     bool
	reliable      bool
}

// Generate emits conservative YARA rules for function symbols in executable
// Intel COFF sections. It never emits a candidate whose function-boundary or
// control-flow invariant cannot be established with available decoder data.
func Generate(ctx context.Context, object *coff.Object, metadata spec.Metadata, args Args, options GenerateOptions) (result Result, resultErr error) {
	if ctx == nil {
		return Result{}, ErrNilContext
	}
	if object == nil {
		return Result{}, ErrNilObject
	}
	if err := args.Validate(); err != nil {
		return Result{}, err
	}
	if args.MaxRules <= 0 {
		return Result{YARA: []byte{}}, nil
	}
	mode, err := machineMode(object.Machine)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("rulegen: generate: %w", err)
	}

	uuid, err := makeUUID(options)
	if err != nil {
		return Result{}, err
	}
	printer := RulePrinter{Metadata: metadata, Args: args, Machine: object.Machine, Now: options.Clock}
	result.RuleName, err = printer.RuleName(uuid)
	if err != nil {
		return Result{}, err
	}

	ranges, err := collectFunctionRanges(object)
	if err != nil {
		return Result{}, err
	}
	factory := options.NewDisassembler
	if factory == nil {
		factory = defaultDisassemblerFactory
	}
	decoder, err := factory(ctx, mode)
	if err != nil {
		return Result{}, fmt.Errorf("rulegen: open %s disassembler: %w", mode, err)
	}
	if decoder == nil {
		return Result{}, errors.New("rulegen: disassembler factory returned nil")
	}
	defer func() {
		if closeErr := decoder.Close(context.Background()); closeErr != nil && resultErr == nil {
			result = Result{}
			resultErr = fmt.Errorf("rulegen: close disassembler: %w", closeErr)
		}
	}()

	result.Functions = make([]FunctionResult, 0, len(ranges))
	allCandidates := make([]candidate, 0)
	seenTargets := make(map[string]bool, len(args.Functions))
	for _, target := range args.Functions {
		seenTargets[target] = false
	}

	for _, function := range ranges {
		if err := ctx.Err(); err != nil {
			return Result{}, fmt.Errorf("rulegen: generate: %w", err)
		}
		if !args.Targets(function.name) {
			continue
		}
		if _, exists := seenTargets[function.name]; exists {
			seenTargets[function.name] = true
		}
		functionIndex := len(result.Functions)
		result.Functions = append(result.Functions, FunctionResult{Name: function.name})
		functionResult := &result.Functions[functionIndex]
		functionCandidates, warnings, omitted, err := generateFunction(ctx, decoder, object.Machine, function, args)
		result.Warnings = append(result.Warnings, warnings...)
		functionResult.Omitted += omitted
		result.OmittedCandidates += omitted
		if err != nil {
			return Result{}, err
		}
		for blockIndex, rule := range functionCandidates {
			functionResult.Candidates++
			result.CandidateCount++
			allCandidates = append(allCandidates, candidate{functionIndex: functionIndex, blockIndex: blockIndex, rule: rule})
		}
	}

	for _, target := range args.Functions {
		if !seenTargets[target] {
			result.Warnings = append(result.Warnings, Warning{
				Code: WarningTargetMissing, Function: target,
				Message: fmt.Sprintf("target function %s is not present in executable COFF sections", target),
			})
		}
	}

	allCandidates = removeDuplicateCandidates(allCandidates, &result)
	sort.SliceStable(allCandidates, func(i, j int) bool {
		return allCandidates[i].rule.Score() > allCandidates[j].rule.Score()
	})
	if len(allCandidates) > args.MaxRules {
		for _, omitted := range allCandidates[args.MaxRules:] {
			result.Functions[omitted.functionIndex].Omitted++
			result.OmittedCandidates++
		}
		allCandidates = allCandidates[:args.MaxRules]
	}
	selected := make(map[int][]candidate)
	for _, selectedCandidate := range allCandidates {
		selected[selectedCandidate.functionIndex] = append(selected[selectedCandidate.functionIndex], selectedCandidate)
		result.Functions[selectedCandidate.functionIndex].Selected++
	}

	groups := make([]FunctionRules, 0, len(selected))
	for functionIndex, functionResult := range result.Functions {
		functionCandidates := selected[functionIndex]
		if len(functionCandidates) == 0 {
			continue
		}
		sort.SliceStable(functionCandidates, func(i, j int) bool {
			return functionCandidates[i].blockIndex < functionCandidates[j].blockIndex
		})
		group := FunctionRules{Name: functionResult.Name, Rules: make([]Rule, len(functionCandidates))}
		for index, selectedCandidate := range functionCandidates {
			group.Rules[index] = selectedCandidate.rule
		}
		groups = append(groups, group)
	}
	result.RuleCount = len(allCandidates)
	if result.RuleCount == 0 {
		result.YARA = []byte{}
		result.Warnings = append(result.Warnings, Warning{
			Code:    WarningNoRules,
			Message: result.RuleName + ": No invariant islands matching Yara rule generator criteria exist",
		})
		return result, nil
	}
	result.YARA, err = printer.Print(result.RuleName, groups)
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func generateFunction(ctx context.Context, decoder x86.Disassembler, machine coff.Machine, function functionRange, args Args) ([]Rule, []Warning, int, error) {
	if function.end <= function.start || uint64(function.end) > uint64(len(function.section.Data)) {
		return nil, nil, 0, fmt.Errorf("%w: function %q range [%#x,%#x) is outside section %q", ErrMalformedObject, function.name, function.start, function.end, function.section.Name)
	}
	code := function.section.Data[function.start:function.end]
	instructions, err := decoder.Disassemble(ctx, code, uint64(function.start))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("rulegen: disassemble function %q: %w", function.name, err)
	}
	if len(instructions) == 0 {
		return nil, nil, 0, nil
	}
	if err := validateInstructions(instructions, function); err != nil {
		return nil, nil, 0, err
	}

	leaders := map[int]struct{}{0: {}}
	flows := make([]flowInfo, len(instructions))
	indexByAddress := make(map[uint64]int, len(instructions))
	for index, instruction := range instructions {
		indexByAddress[instruction.Address] = index
	}
	for index, instruction := range instructions {
		flow := classifyFlow(instruction)
		flows[index] = flow
		if !flow.reliable {
			return nil, []Warning{{
				Code: WarningControlFlow, Function: function.name, Offset: uint32(instruction.Address),
				Message: fmt.Sprintf("omitted %s because control flow at %#x cannot be classified without architecture-specific decoder detail", function.name, instruction.Address),
			}}, 1, nil
		}
		if flow.boundaryAfter && index+1 < len(instructions) {
			leaders[index+1] = struct{}{}
		}
		if flow.hasTarget && flow.target >= uint64(function.start) && flow.target < uint64(function.end) {
			targetIndex, ok := indexByAddress[flow.target]
			if !ok {
				return nil, nil, 0, fmt.Errorf("%w: branch at %#x targets the middle of an instruction at %#x in function %q", ErrMalformedObject, instruction.Address, flow.target, function.name)
			}
			leaders[targetIndex] = struct{}{}
		}
	}
	leaderIndexes := make([]int, 0, len(leaders))
	for index := range leaders {
		leaderIndexes = append(leaderIndexes, index)
	}
	sort.Ints(leaderIndexes)

	analyzed, err := analyzeRelocations(function, instructions, machine)
	if err != nil {
		return nil, nil, 0, err
	}
	optimizer, err := NewRuleOptimizer(args.MaxLength)
	if err != nil {
		return nil, nil, 0, err
	}
	var rules []Rule
	var warnings []Warning
	omitted := 0
	for blockNumber, start := range leaderIndexes {
		end := len(instructions)
		if blockNumber+1 < len(leaderIndexes) {
			end = leaderIndexes[blockNumber+1]
		}
		block := analyzed[start:end]
		if len(block) == 0 {
			continue
		}
		boundaryReason := ""
		if start == 0 {
			boundaryReason = "function prologue"
		}
		if end == len(instructions) || flows[end-1].exit {
			if boundaryReason != "" {
				boundaryReason += " and epilogue"
			} else {
				boundaryReason = "function epilogue"
			}
		}
		if boundaryReason != "" {
			omitted++
			warnings = append(warnings, Warning{
				Code: WarningBoundaryDetail, Function: function.name, Offset: uint32(block[0].Instruction.Address),
				Message: fmt.Sprintf("omitted candidate at %#x: %s invariants require architecture-specific decoder detail", block[0].Instruction.Address, boundaryReason),
			})
			continue
		}
		block = trimTrailingPadding(block)
		if len(block) == 0 {
			omitted++
			continue
		}
		rule, err := NewRule(block)
		if err != nil {
			return nil, nil, 0, err
		}
		rule, err = optimizer.Optimize(rule)
		if err != nil {
			return nil, nil, 0, err
		}
		if rule.TotalValidBytes() < args.MinLength || len(rule.Instructions()) <= 2 {
			omitted++
			continue
		}
		rules = append(rules, rule)
	}
	return rules, warnings, omitted, nil
}

func collectFunctionRanges(object *coff.Object) ([]functionRange, error) {
	sectionOrder := make(map[*coff.Section]int, len(object.Sections))
	for index, section := range object.Sections {
		if section == nil {
			return nil, fmt.Errorf("%w: nil section at index %d", ErrMalformedObject, index)
		}
		sectionOrder[section] = index
	}
	var functions []*coff.Symbol
	for _, symbol := range object.Symbols {
		if symbol == nil || !symbol.IsFunction() || symbol.Section == nil {
			continue
		}
		if _, present := sectionOrder[symbol.Section]; !present {
			return nil, fmt.Errorf("%w: function %q references a section outside the object", ErrMalformedObject, symbol.Name)
		}
		if symbol.Section.IsExecutable() || symbol.Section.GroupName() == ".text" {
			functions = append(functions, symbol)
		}
	}
	sort.SliceStable(functions, func(i, j int) bool {
		left, right := functions[i], functions[j]
		if sectionOrder[left.Section] != sectionOrder[right.Section] {
			return sectionOrder[left.Section] < sectionOrder[right.Section]
		}
		if left.Value != right.Value {
			return left.Value < right.Value
		}
		return left.Name < right.Name
	})
	ranges := make([]functionRange, 0, len(functions))
	for _, symbol := range functions {
		if uint64(symbol.Value) >= uint64(len(symbol.Section.Data)) {
			return nil, fmt.Errorf("%w: function %q starts at %#x outside section %q (%d bytes)", ErrMalformedObject, symbol.Name, symbol.Value, symbol.Section.Name, len(symbol.Section.Data))
		}
		end := uint32(len(symbol.Section.Data))
		for _, boundary := range symbol.Section.SymbolsSorted() {
			if boundary.Value > symbol.Value {
				end = boundary.Value
				break
			}
		}
		if uint64(end) > uint64(len(symbol.Section.Data)) {
			return nil, fmt.Errorf("%w: boundary after function %q is %#x outside section %q", ErrMalformedObject, symbol.Name, end, symbol.Section.Name)
		}
		ranges = append(ranges, functionRange{name: symbol.Name, section: symbol.Section, start: symbol.Value, end: end})
	}
	return ranges, nil
}

func validateInstructions(instructions []x86.Instruction, function functionRange) error {
	expected := uint64(function.start)
	for index, instruction := range instructions {
		if len(instruction.Bytes) == 0 || instruction.Address != expected {
			return fmt.Errorf("%w: decoder returned inconsistent instruction %d for function %q", ErrMalformedObject, index, function.name)
		}
		expected += uint64(len(instruction.Bytes))
	}
	if expected != uint64(function.end) {
		return fmt.Errorf("%w: decoder consumed through %#x, want %#x for function %q", ErrMalformedObject, expected, function.end, function.name)
	}
	return nil
}

func analyzeRelocations(function functionRange, instructions []x86.Instruction, machine coff.Machine) ([]RuleInstruction, error) {
	result := make([]RuleInstruction, len(instructions))
	for index, instruction := range instructions {
		wildcards := make([]bool, len(instruction.Bytes))
		if isE8Call(instruction) {
			for offset := 1; offset < 5; offset++ {
				wildcards[offset] = true
			}
		}
		result[index] = RuleInstruction{Instruction: instruction, Wildcards: wildcards, Score: conservativeScore(instruction)}
	}
	for relocationIndex, relocation := range function.section.Relocations {
		if relocation == nil {
			return nil, fmt.Errorf("%w: nil relocation %d in section %q", ErrMalformedObject, relocationIndex, function.section.Name)
		}
		if relocation.VirtualAddress < function.start || relocation.VirtualAddress >= function.end {
			continue
		}
		width, known := relocationWidth(machine, relocation.Type)
		if !known {
			return nil, fmt.Errorf("%w: unsupported relocation type %#x at %#x", ErrMalformedObject, relocation.Type, relocation.VirtualAddress)
		}
		if width == 0 {
			continue
		}
		if uint64(relocation.VirtualAddress)+uint64(width) > uint64(function.end) {
			return nil, fmt.Errorf("%w: relocation at %#x extends outside function %q", ErrMalformedObject, relocation.VirtualAddress, function.name)
		}
		matched := false
		for instructionIndex := range result {
			instruction := &result[instructionIndex]
			start := instruction.Instruction.Address
			end := start + uint64(len(instruction.Instruction.Bytes))
			relocationStart := uint64(relocation.VirtualAddress)
			if relocationStart < start || relocationStart >= end {
				continue
			}
			if relocationStart+uint64(width) > end {
				return nil, fmt.Errorf("%w: relocation at %#x crosses an instruction boundary in function %q", ErrMalformedObject, relocation.VirtualAddress, function.name)
			}
			first := int(relocationStart - start)
			for offset := first; offset < first+width; offset++ {
				instruction.Wildcards[offset] = true
			}
			matched = true
			break
		}
		if !matched {
			return nil, fmt.Errorf("%w: relocation at %#x does not belong to a decoded instruction in function %q", ErrMalformedObject, relocation.VirtualAddress, function.name)
		}
	}
	return result, nil
}

func classifyFlow(instruction x86.Instruction) flowInfo {
	code := instruction.Bytes
	if len(code) == 0 {
		return flowInfo{reliable: false}
	}
	result := flowInfo{reliable: true}
	setRelative := func(displacement int64) flowInfo {
		result.boundaryAfter = true
		result.hasTarget = true
		base := instruction.Address + uint64(len(code))
		if displacement < 0 && uint64(-displacement) > base {
			result.reliable = false
			return result
		}
		result.target = uint64(int64(base) + displacement)
		return result
	}
	switch {
	case len(code) == 2 && (code[0] == 0xeb || code[0] >= 0x70 && code[0] <= 0x7f || code[0] >= 0xe0 && code[0] <= 0xe3):
		return setRelative(int64(int8(code[1])))
	case len(code) == 5 && code[0] == 0xe9:
		return setRelative(int64(int32(binary.LittleEndian.Uint32(code[1:]))))
	case len(code) == 6 && code[0] == 0x0f && code[1] >= 0x80 && code[1] <= 0x8f:
		return setRelative(int64(int32(binary.LittleEndian.Uint32(code[2:]))))
	case code[0] == 0xc3 || code[0] == 0xcb:
		result.boundaryAfter, result.exit = true, true
		return result
	case len(code) == 3 && (code[0] == 0xc2 || code[0] == 0xca):
		result.boundaryAfter, result.exit = true, true
		return result
	case len(code) >= 2 && code[0] == 0xff && (code[1]>>3)&7 >= 4 && (code[1]>>3)&7 <= 5:
		result.boundaryAfter = true
		return result
	}
	mnemonic := strings.ToLower(instruction.Mnemonic)
	if strings.HasPrefix(mnemonic, "ret") || mnemonic == "jmp" || strings.HasPrefix(mnemonic, "j") || strings.HasPrefix(mnemonic, "loop") {
		result.reliable = false
	}
	return result
}

func trimTrailingPadding(block []RuleInstruction) []RuleInstruction {
	for len(block) > 0 {
		code := block[len(block)-1].Instruction.Bytes
		if len(code) == 1 && (code[0] == 0x90 || code[0] == 0xcc) {
			block = block[:len(block)-1]
			continue
		}
		break
	}
	return block
}

func removeDuplicateCandidates(candidates []candidate, result *Result) []candidate {
	unique := candidates[:0]
	for _, current := range candidates {
		duplicate := false
		for _, previous := range unique {
			if current.rule.Equal(previous.rule) {
				duplicate = true
				break
			}
		}
		if duplicate {
			result.Functions[current.functionIndex].Omitted++
			result.OmittedCandidates++
			continue
		}
		unique = append(unique, current)
	}
	return unique
}

func relocationWidth(machine coff.Machine, relocationType uint16) (int, bool) {
	switch machine {
	case coff.MachineAMD64:
		switch relocationType {
		case 0x0000:
			return 0, true
		case 0x0001:
			return 8, true
		case 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000b:
			return 4, true
		case 0x000a:
			return 2, true
		default:
			return 0, false
		}
	case coff.MachineI386:
		switch relocationType {
		case 0x0000:
			return 0, true
		case 0x0001, 0x0002, 0x000a:
			return 2, true
		case 0x0006, 0x0007, 0x000b, 0x0014:
			return 4, true
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

func machineMode(machine coff.Machine) (x86.Mode, error) {
	switch machine {
	case coff.MachineI386:
		return x86.Mode32, nil
	case coff.MachineAMD64:
		return x86.Mode64, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrUnsupportedMachine, machine)
	}
}

func defaultDisassemblerFactory(ctx context.Context, mode x86.Mode) (x86.Disassembler, error) {
	return x86.NewCapstone(ctx, mode)
}

func makeUUID(options GenerateOptions) (string, error) {
	if options.UUID != nil {
		value, err := options.UUID()
		if err != nil {
			return "", fmt.Errorf("rulegen: UUID source: %w", err)
		}
		return value, nil
	}
	reader := options.Random
	if reader == nil {
		reader = cryptorand.Reader
	}
	var value [16]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return "", fmt.Errorf("rulegen: read UUID randomness: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(value[0:4]),
		binary.BigEndian.Uint16(value[4:6]),
		binary.BigEndian.Uint16(value[6:8]),
		binary.BigEndian.Uint16(value[8:10]),
		value[10:16]), nil
}
