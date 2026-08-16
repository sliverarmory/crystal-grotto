// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package unwindgen

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var objectMu sync.RWMutex

type codeLabel struct {
	name       string
	start      uint32
	end        uint32
	isFunction bool
}

type analyzedFunction struct {
	name         string
	start        uint32
	end          uint32
	instructions []instructionDetail
	prologue     []int
	framePointer bool
	dynamic      bool
	leaf         bool
}

type generationInput struct {
	object        *coff.Object
	text          *coff.Section
	textSymbol    *coff.Symbol
	symbols       map[string]*coff.Symbol
	functions     []analyzedFunction
	catchHandlers map[string]string
}

// Generate analyzes the transformed .text and returns fresh pdata/xdata
// without mutating object. Use Apply when the sections should replace stale
// metadata on the object.
func Generate(ctx context.Context, object *coff.Object, snapshot hooks.Snapshot, options Options) (Result, error) {
	objectMu.RLock()
	defer objectMu.RUnlock()
	return generate(ctx, object, snapshot, options)
}

func generate(ctx context.Context, object *coff.Object, snapshot hooks.Snapshot, options Options) (_ Result, resultErr error) {
	if ctx == nil {
		return Result{}, wrap("input validation", "", 0, false, x86.ErrNilContext)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, wrap("input validation", "", 0, false, err)
	}
	input, err := validateGenerationInput(object, snapshot)
	if err != nil {
		return Result{}, err
	}
	if options.Disassembler != nil && options.Factory != nil {
		return Result{}, wrap("decoder setup", "", 0, false, errors.New("both Disassembler and Factory are set"))
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
		decoder, err = factory(ctx, x86.Mode64)
		if err != nil {
			return Result{}, wrap("decoder setup", "", 0, false, err)
		}
		if decoder == nil {
			return Result{}, wrap("decoder setup", "", 0, false, errors.New("factory returned a nil disassembler"))
		}
		owned = true
	}
	if owned {
		defer func() {
			if closeErr := decoder.Close(context.WithoutCancel(ctx)); closeErr != nil {
				wrapped := wrap("decoder close", "", 0, false, closeErr)
				if resultErr == nil {
					resultErr = wrapped
				} else {
					resultErr = errors.Join(resultErr, wrapped)
				}
			}
		}()
	}

	instructions, err := decoder.Disassemble(ctx, append([]byte(nil), input.text.Data...), 0)
	if err != nil {
		return Result{}, wrap("disassembly", "", 0, false, err)
	}
	functions, err := mapFunctions(ctx, input, instructions)
	if err != nil {
		return Result{}, err
	}
	input.functions = functions
	return emit(input)
}

func validateGenerationInput(object *coff.Object, snapshot hooks.Snapshot) (*generationInput, error) {
	if object == nil {
		return nil, wrap("input validation", "", 0, false, errors.New("nil COFF object"))
	}
	if object.Machine != coff.MachineAMD64 {
		return nil, &UnsupportedError{Reason: fmt.Sprintf("+unwind requires x64, got %s", object.Machine)}
	}
	if snapshot.Machine != "" && snapshot.Machine != "x64" {
		return nil, wrap("catch validation", "", 0, false, fmt.Errorf("hook snapshot machine is %q, want x64", snapshot.Machine))
	}
	input := &generationInput{
		object:        object,
		symbols:       make(map[string]*coff.Symbol, len(object.Symbols)),
		catchHandlers: make(map[string]string, len(snapshot.Catches)),
	}
	sections := make(map[*coff.Section]bool, len(object.Sections))
	sectionNames := make(map[string]bool, len(object.Sections))
	for index, section := range object.Sections {
		if section == nil {
			return nil, wrap("object validation", "", 0, false, fmt.Errorf("section %d is nil", index))
		}
		if section.Name == "" || sectionNames[section.Name] || sections[section] {
			return nil, wrap("object validation", "", 0, false, fmt.Errorf("duplicate or empty section %q", section.Name))
		}
		if section.Object != nil && section.Object != object {
			return nil, wrap("object validation", "", 0, false, fmt.Errorf("section %q belongs to another object", section.Name))
		}
		sections[section] = true
		sectionNames[section.Name] = true
		if section.Name == ".text" {
			input.text = section
		}
	}
	if input.text == nil {
		return nil, wrap("object validation", "", 0, false, errors.New("object has no .text section"))
	}
	if uint64(len(input.text.Data)) > math.MaxUint32 {
		return nil, wrap("object validation", "", 0, false, errors.New(".text exceeds the COFF address space"))
	}
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return nil, wrap("object validation", "", 0, false, fmt.Errorf("symbol %d is nil", index))
		}
		if symbol.Name == "" || input.symbols[symbol.Name] != nil {
			return nil, wrap("object validation", symbol.Name, symbol.Value, true, fmt.Errorf("duplicate or empty symbol %q", symbol.Name))
		}
		if symbol.Section != nil && !sections[symbol.Section] {
			return nil, wrap("object validation", symbol.Name, symbol.Value, true, errors.New("symbol references a section outside the object"))
		}
		input.symbols[symbol.Name] = symbol
		if symbol.Section == input.text && symbol.IsSectionName() && symbol.Name == ".text" {
			input.textSymbol = symbol
		}
		if symbol.IsFunction() && symbol.Section != nil && symbol.Section != input.text {
			return nil, wrap("normalization validation", symbol.Name, symbol.Value, true, fmt.Errorf("function is in %q instead of .text", symbol.Section.Name))
		}
	}
	if input.textSymbol == nil {
		return nil, wrap("object validation", "", 0, false, fmt.Errorf("%w: .text has no static section symbol", ErrInvariant))
	}
	for _, binding := range snapshot.Catches {
		if binding.Function == "" || binding.Handler == "" {
			return nil, wrap("catch validation", binding.Function, 0, false, errors.New("catch function and handler must be non-empty"))
		}
		if _, exists := input.catchHandlers[binding.Function]; exists {
			return nil, wrap("catch validation", binding.Function, 0, false, errors.New("duplicate catch function"))
		}
		function := input.symbols[binding.Function]
		if function == nil {
			return nil, wrap("catch validation", binding.Function, 0, false, fmt.Errorf("No symbol %s in object", binding.Function))
		}
		if !function.IsFunction() || function.Section != input.text {
			return nil, wrap("catch validation", binding.Function, function.Value, true, errors.New("catch target is not a local .text function"))
		}
		handler := input.symbols[binding.Handler]
		if handler == nil {
			return nil, wrap("catch validation", binding.Function, 0, false, fmt.Errorf("No symbol %s in object", binding.Handler))
		}
		if !handler.IsFunction() || handler.Section != input.text {
			return nil, wrap("catch validation", binding.Handler, handler.Value, true, errors.New("catch handler is not a local .text function"))
		}
		input.catchHandlers[binding.Function] = binding.Handler
	}
	return input, nil
}

func mapFunctions(ctx context.Context, input *generationInput, instructions []x86.Instruction) ([]analyzedFunction, error) {
	var labels []codeLabel
	for _, symbol := range input.object.Symbols {
		if symbol.Section != input.text {
			continue
		}
		if uint64(symbol.Value) > uint64(len(input.text.Data)) {
			return nil, wrap("symbol validation", symbol.Name, symbol.Value, true, errors.New("symbol is outside .text"))
		}
		if symbol.IsFunction() || symbol.IsGlobalVariable() {
			labels = append(labels, codeLabel{name: symbol.Name, start: symbol.Value, isFunction: symbol.IsFunction()})
			continue
		}
		if symbol.Type == 0 && symbol.Value > 0 {
			return nil, wrap("normalization validation", symbol.Name, symbol.Value, true, errors.New("non-function/non-code candidate symbol in .text"))
		}
	}
	sort.SliceStable(labels, func(i, j int) bool {
		if labels[i].start != labels[j].start {
			return labels[i].start < labels[j].start
		}
		return labels[i].name < labels[j].name
	})
	for index := range labels {
		if index > 0 && labels[index-1].start == labels[index].start {
			return nil, wrap("normalization validation", labels[index].name, labels[index].start, true, fmt.Errorf("shares its code address with %q", labels[index-1].name))
		}
		if labels[index].start == uint32(len(input.text.Data)) {
			return nil, wrap("normalization validation", labels[index].name, labels[index].start, true, errors.New("zero-length code label at end of .text"))
		}
		labels[index].end = uint32(len(input.text.Data))
		if index+1 < len(labels) {
			labels[index].end = labels[index+1].start
		}
	}

	boundaries := map[uint32]bool{0: true}
	expected := uint64(0)
	labelIndex := -1
	byName := make(map[string]*analyzedFunction)
	var functions []analyzedFunction
	for _, label := range labels {
		if label.isFunction {
			functions = append(functions, analyzedFunction{name: label.name, start: label.start, end: label.end})
			byName[label.name] = &functions[len(functions)-1]
		}
	}
	// Appending above can move the backing array, so refresh pointers once its
	// final size is known.
	for index := range functions {
		byName[functions[index].name] = &functions[index]
	}
	for index, instruction := range instructions {
		if err := ctx.Err(); err != nil {
			return nil, wrap("instruction validation", "", uint32(expected), true, err)
		}
		if instruction.Address != expected || len(instruction.Bytes) == 0 {
			return nil, wrap("instruction validation", "", uint32(expected), true, fmt.Errorf("instruction %d starts at %#x with %d bytes", index, instruction.Address, len(instruction.Bytes)))
		}
		end := expected + uint64(len(instruction.Bytes))
		if end > uint64(len(input.text.Data)) || !bytes.Equal(instruction.Bytes, input.text.Data[expected:end]) {
			return nil, wrap("instruction validation", "", uint32(expected), true, fmt.Errorf("instruction %d does not match .text", index))
		}
		for labelIndex+1 < len(labels) && labels[labelIndex+1].start <= uint32(expected) {
			labelIndex++
		}
		if labelIndex >= 0 && labels[labelIndex].isFunction && uint32(expected) < labels[labelIndex].end {
			function := byName[labels[labelIndex].name]
			detail, err := classifyInstruction(function.name, instruction)
			if err != nil {
				return nil, err
			}
			function.instructions = append(function.instructions, detail)
		}
		expected = end
		boundaries[uint32(expected)] = true
	}
	if expected != uint64(len(input.text.Data)) {
		return nil, wrap("instruction validation", "", uint32(expected), true, fmt.Errorf("decoder consumed %d of %d bytes", expected, len(input.text.Data)))
	}
	for _, label := range labels {
		if !boundaries[label.start] {
			return nil, wrap("instruction validation", label.name, label.start, true, errors.New("code label is not on an instruction boundary"))
		}
	}
	for index := range functions {
		function := &functions[index]
		if len(function.instructions) == 0 {
			return nil, wrap("instruction validation", function.name, function.start, true, errors.New("function has no decoded instructions"))
		}
		analyzeBookends(function)
		if function.dynamic && !function.framePointer {
			return nil, &DynamicFrameError{Function: function.name}
		}
	}
	return functions, nil
}

func analyzeBookends(function *analyzedFunction) {
	prologue := make(map[int]bool)
	cursor := 0
	for cursor < len(function.instructions) {
		detail := function.instructions[cursor]
		switch detail.kind {
		case kindPush, kindSubRSP:
			prologue[cursor] = true
			function.prologue = append(function.prologue, cursor)
			cursor++
			continue
		case kindFrameMOV, kindFrameLEA:
			prologue[cursor] = true
			function.prologue = append(function.prologue, cursor)
			function.framePointer = true
			cursor++
		default:
			// PrologueWalk consumes the first non-prologue instruction before
			// looking for an exit.
			cursor++
		}
		break
	}
	bookend := make(map[int]bool, len(prologue)+4)
	for index := range prologue {
		bookend[index] = true
	}
	for index := cursor; index < len(function.instructions); index++ {
		kind := function.instructions[index].kind
		if kind != kindReturn && kind != kindJumpRCX {
			continue
		}
		bookend[index] = true
		for previous := index - 1; previous >= 0; previous-- {
			kind = function.instructions[previous].kind
			if kind != kindPop && kind != kindAddRSP {
				break
			}
			bookend[previous] = true
		}
		break
	}
	function.leaf = len(function.prologue) == 0
	for index, detail := range function.instructions {
		if detail.kind == kindCall {
			function.leaf = false
		}
		if bookend[index] {
			continue
		}
		switch detail.kind {
		case kindSubRSP, kindAddRSP, kindPop, kindStackDynamic:
			function.dynamic = true
		}
	}
}

func emit(input *generationInput) (Result, error) {
	pdata := coff.NewSection(".pdata", nil)
	xdata := coff.NewSection(".xdata", nil)
	pdata.Alignment, xdata.Alignment = 4, 4
	result := Result{PDATA: pdata, XDATA: xdata}
	for _, function := range input.functions {
		if function.leaf {
			result.SkippedLeaves = append(result.SkippedLeaves, function.name)
			continue
		}
		if uint64(len(pdata.Data))+12 > math.MaxUint32 || uint64(len(xdata.Data)) > math.MaxUint32 {
			return Result{}, wrap("section emission", function.name, function.start, true, errors.New("generated unwind sections exceed 32 bits"))
		}
		unwindOffset := uint32(len(xdata.Data))
		handler := input.catchHandlers[function.name]
		info, slots, err := encodeUnwindInfo(function, handler != "")
		if err != nil {
			return Result{}, err
		}
		rowOffset := uint32(len(pdata.Data))
		pdata.Data = binary.LittleEndian.AppendUint32(pdata.Data, function.start)
		pdata.Data = binary.LittleEndian.AppendUint32(pdata.Data, function.end)
		pdata.Data = binary.LittleEndian.AppendUint32(pdata.Data, unwindOffset)
		pdata.Relocations = append(pdata.Relocations,
			&coff.Relocation{Section: pdata, VirtualAddress: rowOffset, SymbolName: ".text", Symbol: input.textSymbol, Type: coff.RelAMD64Addr32NB},
			&coff.Relocation{Section: pdata, VirtualAddress: rowOffset + 4, SymbolName: ".text", Symbol: input.textSymbol, Type: coff.RelAMD64Addr32NB},
			&coff.Relocation{Section: pdata, VirtualAddress: rowOffset + 8, SymbolName: ".xdata", Type: coff.RelAMD64Addr32NB},
		)
		xdata.Data = append(xdata.Data, info...)
		if handler != "" {
			if slots%2 != 0 {
				xdata.Data = append(xdata.Data, 0, 0)
			}
			handlerSymbol := input.symbols[handler]
			handlerOffset := uint32(len(xdata.Data))
			xdata.Data = binary.LittleEndian.AppendUint32(xdata.Data, handlerSymbol.Value)
			xdata.Relocations = append(xdata.Relocations, &coff.Relocation{
				Section: xdata, VirtualAddress: handlerOffset, SymbolName: ".text", Symbol: input.textSymbol, Type: coff.RelAMD64Addr32NB,
			})
		}
		for len(xdata.Data)%4 != 0 {
			xdata.Data = append(xdata.Data, 0)
		}
		result.Functions = append(result.Functions, Function{
			Name: function.name, BeginAddress: function.start, EndAddress: function.end, UnwindOffset: unwindOffset, Handler: handler,
		})
	}
	pdata.SizeOfRawData = uint32(len(pdata.Data))
	xdata.SizeOfRawData = uint32(len(xdata.Data))
	return result, nil
}

func encodeUnwindInfo(function analyzedFunction, handler bool) ([]byte, int, error) {
	if len(function.instructions) == 0 {
		return nil, 0, wrap("unwind encoding", function.name, function.start, true, errors.New("function has no instructions"))
	}
	first := function.instructions[0].instruction.Address
	var entries [][]byte
	count, sizeOfPrologue := 0, uint64(0)
	frameRegister, frameOffset := uint8(0), uint8(0)
	for _, index := range function.prologue {
		detail := function.instructions[index]
		next := detail.instruction.Address + uint64(len(detail.instruction.Bytes))
		if next < first || next-first > math.MaxUint8 {
			return nil, 0, unsupported(function.name, detail.instruction, "prologue offset exceeds the x64 unwind-code field")
		}
		offset := byte(next - first)
		entry := []byte{}
		switch detail.kind {
		case kindPush:
			op, opInfo := uint8(coff.UnwindOpAllocSmall), uint8(0)
			if isNonVolatile(detail.register) {
				op, opInfo = coff.UnwindOpPushNonVol, detail.register
			}
			entry = append(entry, offset, (opInfo<<4)|op)
			count++
		case kindSubRSP:
			if detail.amount < 8 || detail.amount%8 != 0 {
				return nil, 0, unsupported(function.name, detail.instruction, "stack allocation is not an encodable positive multiple of 8")
			}
			switch {
			case detail.amount <= 128:
				opInfo := uint8((detail.amount - 8) / 8)
				entry = append(entry, offset, (opInfo<<4)|coff.UnwindOpAllocSmall)
				count++
			case detail.amount <= 524280:
				entry = append(entry, offset, coff.UnwindOpAllocLarge)
				entry = binary.LittleEndian.AppendUint16(entry, uint16(detail.amount/8))
				count += 2
			default:
				entry = append(entry, offset, (1<<4)|coff.UnwindOpAllocLarge)
				entry = binary.LittleEndian.AppendUint32(entry, detail.amount)
				count += 3
			}
		case kindFrameMOV, kindFrameLEA:
			frameRegister = detail.register
			frameOffset = uint8(detail.frameOffset / 16)
			entry = append(entry, offset, coff.UnwindOpSetFPReg)
			count++
		default:
			return nil, 0, unsupported(function.name, detail.instruction, "unexpected prologue instruction")
		}
		if count > math.MaxUint8 {
			return nil, 0, unsupported(function.name, detail.instruction, "unwind-code count exceeds 255 slots")
		}
		entries = append(entries, entry)
		sizeOfPrologue = next - first
	}
	flags := uint8(0)
	if handler {
		flags = 0x08
	}
	encoded := []byte{1 | flags, byte(sizeOfPrologue), byte(count), frameRegister | frameOffset<<4}
	for index := len(entries) - 1; index >= 0; index-- {
		encoded = append(encoded, entries[index]...)
	}
	return encoded, count, nil
}

func isNonVolatile(register uint8) bool {
	switch register {
	case 3, 5, 6, 7, 12, 13, 14, 15:
		return true
	default:
		return false
	}
}

func wrap(stage, function string, offset uint32, hasOffset bool, err error) *Error {
	return &Error{Stage: stage, Function: function, Offset: offset, HasOffset: hasOffset, Err: err}
}
