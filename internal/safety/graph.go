// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package safety

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

type codeNode struct {
	name       string
	start      uint32
	end        uint32
	isFunction bool
}

type preparedObject struct {
	object        *coff.Object
	text          *coff.Section
	mode          x86.Mode
	nodes         []codeNode
	nodesByName   map[string]codeNode
	symbolsByName map[string]*coff.Symbol
	symbolSet     map[*coff.Symbol]bool
}

type decodedInstruction struct {
	instruction x86.Instruction
	node        *codeNode
	relocations []*coff.Relocation
}

type relocationResolution struct {
	targets      []string
	kind         EdgeKind
	controlKnown bool
}

// BuildGraph validates and analyzes one normalized x86/x64 COFF object. The
// returned graph owns no mutable object or decoder state and may be checked
// concurrently.
func BuildGraph(ctx context.Context, object *coff.Object, options Options) (_ *Graph, resultErr error) {
	if ctx == nil {
		return nil, analysisError("input validation", "", 0, false, x86.ErrNilContext)
	}
	if err := ctx.Err(); err != nil {
		return nil, analysisError("input validation", "", 0, false, err)
	}
	prepared, err := prepareObject(object)
	if err != nil {
		return nil, err
	}

	if options.Disassembler != nil && options.Factory != nil {
		return nil, analysisError("decoder setup", "", 0, false, errors.New("both Disassembler and Factory are set"))
	}
	decoder := options.Disassembler
	owned := false
	if decoder == nil {
		factory := options.Factory
		if factory == nil {
			factory = func(ctx context.Context, mode x86.Mode) (x86.Disassembler, error) {
				return x86.NewCapstone(ctx, mode)
			}
		}
		decoder, err = factory(ctx, prepared.mode)
		if err != nil {
			return nil, analysisError("decoder setup", "", 0, false, err)
		}
		if decoder == nil {
			return nil, analysisError("decoder setup", "", 0, false, errors.New("factory returned a nil disassembler"))
		}
		owned = true
	}
	if owned {
		defer func() {
			closeErr := decoder.Close(context.WithoutCancel(ctx))
			if closeErr == nil {
				return
			}
			wrapped := analysisError("decoder close", "", 0, false, closeErr)
			if resultErr == nil {
				resultErr = wrapped
			} else {
				resultErr = errors.Join(resultErr, wrapped)
			}
		}()
	}

	instructions, err := decoder.Disassemble(ctx, append([]byte(nil), prepared.text.Data...), 0)
	if err != nil {
		return nil, analysisError("disassembly", "", 0, false, err)
	}
	decoded, boundaries, err := validateInstructions(ctx, prepared, instructions)
	if err != nil {
		return nil, err
	}
	if err := attachRelocations(ctx, prepared, decoded); err != nil {
		return nil, err
	}
	return buildEdges(ctx, prepared, decoded, boundaries)
}

func prepareObject(object *coff.Object) (*preparedObject, error) {
	if object == nil {
		return nil, analysisError("object validation", "", 0, false, errors.New("nil COFF object"))
	}
	var mode x86.Mode
	switch object.Machine {
	case coff.MachineI386:
		mode = x86.Mode32
	case coff.MachineAMD64:
		mode = x86.Mode64
	default:
		return nil, analysisError("object validation", "", 0, false, fmt.Errorf("unsupported machine %s", object.Machine))
	}
	if len(object.Sections) == 0 {
		return nil, analysisError("object validation", "", 0, false, errors.New("object has no sections"))
	}
	sections := make(map[*coff.Section]bool, len(object.Sections))
	sectionNames := make(map[string]bool, len(object.Sections))
	var text *coff.Section
	for index, section := range object.Sections {
		if section == nil {
			return nil, analysisError("object validation", "", 0, false, fmt.Errorf("section %d is nil", index))
		}
		if section.Name == "" {
			return nil, analysisError("object validation", "", 0, false, fmt.Errorf("section %d has an empty name", index))
		}
		if sections[section] || sectionNames[section.Name] {
			return nil, analysisError("object validation", "", 0, false, fmt.Errorf("duplicate section %q", section.Name))
		}
		if section.Object != nil && section.Object != object {
			return nil, analysisError("object validation", "", 0, false, fmt.Errorf("section %q belongs to another object", section.Name))
		}
		sections[section] = true
		sectionNames[section.Name] = true
		if section.Name == ".text" {
			text = section
		}
	}
	if text == nil {
		return nil, analysisError("object validation", "", 0, false, errors.New("object has no .text section"))
	}
	if uint64(len(text.Data)) > math.MaxUint32 {
		return nil, analysisError("object validation", "", 0, false, errors.New(".text exceeds the 32-bit COFF address space"))
	}

	prepared := &preparedObject{
		object:        object,
		text:          text,
		mode:          mode,
		nodesByName:   make(map[string]codeNode),
		symbolsByName: make(map[string]*coff.Symbol, len(object.Symbols)),
		symbolSet:     make(map[*coff.Symbol]bool, len(object.Symbols)),
	}
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return nil, analysisError("object validation", "", 0, false, fmt.Errorf("symbol %d is nil", index))
		}
		if symbol.Name == "" {
			return nil, analysisError("object validation", "", 0, false, fmt.Errorf("symbol %d has an empty name", index))
		}
		if prepared.symbolsByName[symbol.Name] != nil {
			return nil, analysisError("object validation", "", 0, false, fmt.Errorf("duplicate symbol %q", symbol.Name))
		}
		if symbol.Section != nil && !sections[symbol.Section] {
			return nil, analysisError("object validation", symbol.Name, symbol.Value, true, errors.New("symbol references a section outside the object"))
		}
		prepared.symbolsByName[symbol.Name] = symbol
		prepared.symbolSet[symbol] = true
		if symbol.IsFunction() && symbol.Section != nil && symbol.Section != text {
			return nil, analysisError("normalization validation", symbol.Name, symbol.Value, true, fmt.Errorf("function is in %q instead of .text", symbol.Section.Name))
		}
		if symbol.Section != text {
			continue
		}
		if uint64(symbol.Value) > uint64(len(text.Data)) {
			return nil, analysisError("object validation", symbol.Name, symbol.Value, true, errors.New("symbol is outside .text"))
		}
		if symbol.IsFunction() || symbol.IsGlobalVariable() {
			prepared.nodes = append(prepared.nodes, codeNode{
				name:       symbol.Name,
				start:      symbol.Value,
				isFunction: symbol.IsFunction(),
			})
			continue
		}
		if symbol.Type == 0 && symbol.Value > 0 {
			return nil, analysisError("normalization validation", symbol.Name, symbol.Value, true, errors.New("non-function/non-code candidate symbol in .text"))
		}
	}
	if len(prepared.nodes) == 0 {
		return nil, analysisError("normalization validation", "", 0, false, errors.New(".text has no function or code-data labels"))
	}
	sort.SliceStable(prepared.nodes, func(i, j int) bool {
		if prepared.nodes[i].start != prepared.nodes[j].start {
			return prepared.nodes[i].start < prepared.nodes[j].start
		}
		return prepared.nodes[i].name < prepared.nodes[j].name
	})
	for index := range prepared.nodes {
		node := &prepared.nodes[index]
		if index > 0 && prepared.nodes[index-1].start == node.start {
			return nil, analysisError("normalization validation", node.name, node.start, true, fmt.Errorf("shares its code address with %q", prepared.nodes[index-1].name))
		}
		if node.start == uint32(len(text.Data)) {
			return nil, analysisError("normalization validation", node.name, node.start, true, errors.New("zero-length code label at end of .text"))
		}
		node.end = uint32(len(text.Data))
		if index+1 < len(prepared.nodes) {
			node.end = prepared.nodes[index+1].start
		}
		prepared.nodesByName[node.name] = *node
	}
	return prepared, nil
}

func validateInstructions(ctx context.Context, prepared *preparedObject, instructions []x86.Instruction) ([]decodedInstruction, map[uint32]bool, error) {
	data := prepared.text.Data
	decoded := make([]decodedInstruction, 0, len(instructions))
	boundaries := make(map[uint32]bool, len(instructions)+1)
	expected := uint64(0)
	boundaries[0] = true
	nodeIndex := -1
	for index, instruction := range instructions {
		if err := ctx.Err(); err != nil {
			return nil, nil, analysisError("instruction validation", "", uint32(expected), true, err)
		}
		if instruction.Address != expected {
			return nil, nil, analysisError("instruction validation", "", uint32(expected), true, fmt.Errorf("instruction %d starts at %#x", index, instruction.Address))
		}
		if len(instruction.Bytes) == 0 {
			return nil, nil, analysisError("instruction validation", "", uint32(expected), true, fmt.Errorf("instruction %d has no bytes", index))
		}
		end := expected + uint64(len(instruction.Bytes))
		if end > uint64(len(data)) {
			return nil, nil, analysisError("instruction validation", "", uint32(expected), true, fmt.Errorf("instruction %d extends beyond .text", index))
		}
		if !bytes.Equal(instruction.Bytes, data[expected:end]) {
			return nil, nil, analysisError("instruction validation", "", uint32(expected), true, fmt.Errorf("instruction %d bytes differ from .text", index))
		}
		for nodeIndex+1 < len(prepared.nodes) && prepared.nodes[nodeIndex+1].start <= uint32(expected) {
			nodeIndex++
		}
		var owner *codeNode
		if nodeIndex >= 0 && uint32(expected) < prepared.nodes[nodeIndex].end {
			owner = &prepared.nodes[nodeIndex]
		}
		decoded = append(decoded, decodedInstruction{instruction: instruction, node: owner})
		expected = end
		boundaries[uint32(expected)] = true
	}
	if expected != uint64(len(data)) {
		return nil, nil, analysisError("instruction validation", "", uint32(expected), true, fmt.Errorf("decoder consumed %d of %d bytes", expected, len(data)))
	}
	for _, node := range prepared.nodes {
		if !boundaries[node.start] {
			return nil, nil, analysisError("instruction validation", node.name, node.start, true, errors.New("code label is not on an instruction boundary"))
		}
	}
	return decoded, boundaries, nil
}

func attachRelocations(ctx context.Context, prepared *preparedObject, instructions []decodedInstruction) error {
	seen := make(map[uint32]bool, len(prepared.text.Relocations))
	for index, relocation := range prepared.text.Relocations {
		if err := ctx.Err(); err != nil {
			return analysisError("relocation validation", "", 0, false, err)
		}
		if relocation == nil {
			return analysisError("relocation validation", "", 0, false, fmt.Errorf("relocation %d is nil", index))
		}
		if relocation.Section != prepared.text {
			return analysisError("relocation validation", "", relocation.VirtualAddress, true, errors.New("relocation does not identify .text as its parent"))
		}
		if seen[relocation.VirtualAddress] {
			return analysisError("relocation validation", "", relocation.VirtualAddress, true, errors.New("multiple relocations share one address"))
		}
		seen[relocation.VirtualAddress] = true
		width, err := relocationWidth(prepared.object.Machine, relocation.Type)
		if err != nil {
			return analysisError("relocation validation", "", relocation.VirtualAddress, true, err)
		}
		at := uint64(relocation.VirtualAddress)
		if at+uint64(width) > uint64(len(prepared.text.Data)) {
			return analysisError("relocation validation", "", relocation.VirtualAddress, true, fmt.Errorf("%d-byte relocation field is outside .text", width))
		}
		instructionIndex := sort.Search(len(instructions), func(i int) bool {
			start := instructions[i].instruction.Address
			return start+uint64(len(instructions[i].instruction.Bytes)) > at
		})
		if instructionIndex == len(instructions) {
			return analysisError("relocation validation", "", relocation.VirtualAddress, true, errors.New("relocation is not inside an instruction"))
		}
		instruction := &instructions[instructionIndex]
		start := instruction.instruction.Address
		end := start + uint64(len(instruction.instruction.Bytes))
		if at < start || at+uint64(width) > end {
			return analysisError("relocation validation", nodeName(instruction.node), relocation.VirtualAddress, true, errors.New("relocation field crosses an instruction boundary"))
		}
		if relocation.Symbol != nil && !prepared.symbolSet[relocation.Symbol] {
			return analysisError("relocation validation", nodeName(instruction.node), relocation.VirtualAddress, true, errors.New("relocation symbol is not in the object symbol table"))
		}
		instruction.relocations = append(instruction.relocations, relocation)
	}
	return nil
}

func buildEdges(ctx context.Context, prepared *preparedObject, instructions []decodedInstruction, boundaries map[uint32]bool) (*Graph, error) {
	graph := &Graph{
		machine:   prepared.object.Machine,
		adjacency: make(map[string][]Edge, len(prepared.nodes)),
		rootable:  make(map[string]bool),
	}
	for _, node := range prepared.nodes {
		graph.adjacency[node.name] = make([]Edge, 0)
		if node.isFunction {
			graph.functions = append(graph.functions, node.name)
			graph.rootable[node.name] = true
		}
	}
	seenEdges := make(map[Edge]bool)
	addEdge := func(edge Edge) {
		if seenEdges[edge] {
			return
		}
		seenEdges[edge] = true
		graph.edges = append(graph.edges, edge)
		graph.adjacency[edge.From] = append(graph.adjacency[edge.From], edge)
	}

	for _, decoded := range instructions {
		if decoded.node == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, analysisError("edge discovery", decoded.node.name, uint32(decoded.instruction.Address), true, err)
		}
		semantics, err := decodeSemantics(decoded.instruction, prepared.mode)
		if err != nil {
			return nil, analysisError("instruction semantics", decoded.node.name, uint32(decoded.instruction.Address), true, err)
		}
		controlKnown := false
		for _, relocation := range decoded.relocations {
			resolution, err := resolveRelocation(prepared, decoded, relocation, boundaries, semantics.flow != flowNone)
			if err != nil {
				return nil, err
			}
			controlKnown = controlKnown || resolution.controlKnown
			for _, target := range resolution.targets {
				addEdge(Edge{From: decoded.node.name, To: target, Offset: uint32(decoded.instruction.Address), Kind: resolution.kind})
			}
		}

		if semantics.flow != flowNone {
			kind := EdgeDirectCall
			if semantics.flow == flowJump {
				kind = EdgeDirectJump
			}
			if len(decoded.relocations) != 0 {
				if !controlKnown {
					return nil, analysisError("control-flow resolution", decoded.node.name, uint32(decoded.instruction.Address), true, errors.New("control-flow relocation does not resolve a code or external target"))
				}
				continue
			}
			if semantics.direct {
				target, err := resolveAddress(prepared, semantics.directTarget, boundaries, true)
				if err != nil {
					return nil, analysisError("direct control-flow resolution", decoded.node.name, uint32(decoded.instruction.Address), true, err)
				}
				addEdge(Edge{From: decoded.node.name, To: target, Offset: uint32(decoded.instruction.Address), Kind: kind})
				continue
			}
			if semantics.ripReference {
				target, err := resolveAddress(prepared, semantics.ripTarget, boundaries, true)
				if err != nil {
					return nil, analysisError("RIP-relative control-flow resolution", decoded.node.name, uint32(decoded.instruction.Address), true, err)
				}
				addEdge(Edge{From: decoded.node.name, To: target, Offset: uint32(decoded.instruction.Address), Kind: kind})
				continue
			}
			return nil, analysisError("indirect control-flow resolution", decoded.node.name, uint32(decoded.instruction.Address), true, errors.New("indirect CALL/JMP has no statically named target"))
		}

		if semantics.ripReference && len(decoded.relocations) == 0 {
			if semantics.ripTarget >= uint64(len(prepared.text.Data)) {
				return nil, analysisError("RIP-relative reference resolution", decoded.node.name, uint32(decoded.instruction.Address), true, fmt.Errorf("target %#x is outside .text without a relocation", semantics.ripTarget))
			}
			target, err := resolveAddress(prepared, semantics.ripTarget, boundaries, false)
			if err != nil {
				return nil, analysisError("RIP-relative reference resolution", decoded.node.name, uint32(decoded.instruction.Address), true, err)
			}
			addEdge(Edge{From: decoded.node.name, To: target, Offset: uint32(decoded.instruction.Address), Kind: EdgeRIPReference})
		}
	}
	return graph, nil
}

func resolveRelocation(prepared *preparedObject, decoded decodedInstruction, relocation *coff.Relocation, boundaries map[uint32]bool, controlFlow bool) (relocationResolution, error) {
	resolution := relocationResolution{kind: EdgeRelocation}
	name := relocation.SymbolName
	symbol := relocation.Symbol
	if symbol != nil {
		if name != "" && name != symbol.Name {
			return resolution, analysisError("relocation resolution", decoded.node.name, relocation.VirtualAddress, true, fmt.Errorf("symbol name %q disagrees with referenced symbol %q", name, symbol.Name))
		}
		name = symbol.Name
	}
	if name == "" {
		return resolution, analysisError("relocation resolution", decoded.node.name, relocation.VirtualAddress, true, errors.New("relocation has no symbol name"))
	}
	indexed := prepared.symbolsByName[name]
	if symbol == nil {
		symbol = indexed
	} else if indexed != nil && indexed != symbol {
		return resolution, analysisError("relocation resolution", decoded.node.name, relocation.VirtualAddress, true, fmt.Errorf("symbol table lookup for %q is inconsistent", name))
	}

	if strings.HasPrefix(name, ".refptr.") {
		targetName := strings.TrimPrefix(name, ".refptr.")
		if targetName == "" {
			return resolution, analysisError("reference-pointer resolution", decoded.node.name, relocation.VirtualAddress, true, errors.New("empty .refptr target"))
		}
		resolution.kind = EdgeReferencePointer
		resolution.controlKnown = true
		if dangerSymbol(prepared.object.Machine, targetName) {
			resolution.targets = []string{dangerName(prepared.object.Machine)}
			return resolution, nil
		}
		target := prepared.symbolsByName[targetName]
		if target == nil || target.Section == nil {
			// A named, undefined .refptr target is an external reference. It
			// cannot lead back into this normalized object's local code.
			return resolution, nil
		}
		if target.Section != prepared.text {
			return resolution, nil
		}
		node, err := localSymbolNode(prepared, target)
		if err != nil {
			return resolution, analysisError("reference-pointer resolution", decoded.node.name, relocation.VirtualAddress, true, err)
		}
		resolution.targets = []string{node}
		return resolution, nil
	}

	if dangerSymbol(prepared.object.Machine, name) {
		resolution.targets = []string{dangerName(prepared.object.Machine)}
		resolution.controlKnown = true
		return resolution, nil
	}
	if symbol == nil || symbol.Section == nil {
		// COFF undefined symbols are statically named external references.
		resolution.controlKnown = true
		return resolution, nil
	}
	if symbol.Section != prepared.text {
		if strings.HasPrefix(name, "__imp_") || strings.HasPrefix(name, "_imp__") {
			resolution.controlKnown = true
		}
		return resolution, nil
	}

	if symbol.IsSectionName() || symbol.Name == ".text" {
		node, err := resolveSectionRelocation(prepared, relocation, boundaries, controlFlow)
		if err != nil {
			return resolution, analysisError("local section relocation resolution", decoded.node.name, relocation.VirtualAddress, true, err)
		}
		resolution.targets = []string{node}
		resolution.controlKnown = true
		return resolution, nil
	}
	node, err := localSymbolNode(prepared, symbol)
	if err != nil {
		return resolution, analysisError("local relocation resolution", decoded.node.name, relocation.VirtualAddress, true, err)
	}
	resolution.targets = []string{node}
	resolution.controlKnown = true
	return resolution, nil
}

func localSymbolNode(prepared *preparedObject, symbol *coff.Symbol) (string, error) {
	if symbol == nil || symbol.Section != prepared.text {
		return "", errors.New("relocation target is not local .text")
	}
	if node, ok := prepared.nodesByName[symbol.Name]; ok {
		return node.name, nil
	}
	if !symbol.IsSectionName() && symbol.Name != ".text" {
		return "", fmt.Errorf("local symbol %q is not a function or code-data label", symbol.Name)
	}
	// Section-symbol relocations carry the local target as their addend.
	return "", errors.New("section-symbol target requires relocation addend")
}

func resolveSectionRelocation(prepared *preparedObject, relocation *coff.Relocation, boundaries map[uint32]bool, requireBoundary bool) (string, error) {
	width, err := relocationWidth(prepared.object.Machine, relocation.Type)
	if err != nil {
		return "", err
	}
	at := int(relocation.VirtualAddress)
	var addend int64
	switch width {
	case 2:
		addend = int64(int16(binary.LittleEndian.Uint16(prepared.text.Data[at : at+2])))
	case 4:
		addend = int64(int32(binary.LittleEndian.Uint32(prepared.text.Data[at : at+4])))
	case 8:
		value := binary.LittleEndian.Uint64(prepared.text.Data[at : at+8])
		if value > math.MaxInt64 {
			return "", errors.New("section relocation addend exceeds int64")
		}
		addend = int64(value)
	default:
		return "", fmt.Errorf("unsupported section relocation width %d", width)
	}
	if addend < 0 {
		return "", fmt.Errorf("negative .text section addend %d", addend)
	}
	return resolveAddress(prepared, uint64(addend), boundaries, requireBoundary)
}

func resolveAddress(prepared *preparedObject, address uint64, boundaries map[uint32]bool, requireBoundary bool) (string, error) {
	if address >= uint64(len(prepared.text.Data)) {
		return "", fmt.Errorf("target %#x is outside .text", address)
	}
	value := uint32(address)
	if requireBoundary && !boundaries[value] {
		return "", fmt.Errorf("target %#x is not an instruction boundary", address)
	}
	index := sort.Search(len(prepared.nodes), func(i int) bool { return prepared.nodes[i].start > value }) - 1
	if index < 0 || value >= prepared.nodes[index].end {
		return "", fmt.Errorf("target %#x is not owned by a code label", address)
	}
	return prepared.nodes[index].name, nil
}

func relocationWidth(machine coff.Machine, relocationType uint16) (int, error) {
	switch machine {
	case coff.MachineI386:
		switch relocationType {
		case coff.RelI386Dir32, 0x0007, 0x000b, coff.RelI386Rel32:
			return 4, nil
		case 0x000a:
			return 2, nil
		}
	case coff.MachineAMD64:
		switch relocationType {
		case coff.RelAMD64Addr64:
			return 8, nil
		case 0x0002, coff.RelAMD64Addr32NB, coff.RelAMD64Rel32, coff.RelAMD64Rel32_1, coff.RelAMD64Rel32_2, coff.RelAMD64Rel32_3, coff.RelAMD64Rel32_4, coff.RelAMD64Rel32_5, 0x000b:
			return 4, nil
		case 0x000a:
			return 2, nil
		}
	}
	return 0, fmt.Errorf("unsupported %s relocation type %#x", machine, relocationType)
}

func nodeName(node *codeNode) string {
	if node == nil {
		return ""
	}
	return node.name
}

func analysisError(stage, function string, offset uint32, hasOffset bool, err error) *AnalysisError {
	return &AnalysisError{Stage: stage, Function: function, Offset: offset, HasOffset: hasOffset, Err: err}
}
