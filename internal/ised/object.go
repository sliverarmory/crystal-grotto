// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package ised

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var (
	// ErrNilContext identifies a nil context at the high-level object boundary.
	ErrNilContext = errors.New("ised: nil context")

	// ErrInvalidObject identifies malformed COFF relationships discovered while
	// lifting or rebasing an object.
	ErrInvalidObject = errors.New("ised: invalid COFF object")
)

// DisassemblerFactory opens a decoder for one LiftObject operation.
type DisassemblerFactory func(context.Context, x86.Mode) (x86.Disassembler, error)

// ObjectOptions controls the high-level COFF lift/plan/rewrite operation.
// Disassembler is caller-owned. A decoder returned by NewDisassembler is
// closed by LiftObject. The two fields are mutually exclusive.
type ObjectOptions struct {
	Unwind        bool
	ReturnAddress string
	Random        io.Reader

	Disassembler    x86.Disassembler
	NewDisassembler DisassemblerFactory
}

// ApplyObject is the engine-facing ised operation. It derives the conservative
// semantic program from object, applies upstream selection semantics, and
// transactionally rebases the resulting object with the built-in backend.
// It is intended to run after mutate and before regdance.
func ApplyObject(ctx context.Context, object *coff.Object, configuration Configuration, options ObjectOptions) (*coff.Object, Program, Plan, error) {
	program, err := LiftObject(ctx, object, options)
	if err != nil {
		return nil, Program{}, Plan{}, err
	}
	result, plan, err := Apply(object, program, configuration, PlanOptions{
		Unwind: options.Unwind,
		Random: options.Random,
	}, RebaseBackend{Context: ctx})
	if err != nil {
		return nil, cloneProgram(program), plan, err
	}
	return result, cloneProgram(program), plan, nil
}

// LiftObject builds the Iced-equivalent subset that can be proven from
// Capstone instruction boundaries and raw x86/x64 encodings. Formatted
// Capstone operands are used only as a signal to fail closed on an otherwise
// unclassified RIP-relative instruction.
func LiftObject(ctx context.Context, object *coff.Object, options ObjectOptions) (Program, error) {
	if ctx == nil {
		return Program{}, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return Program{}, fmt.Errorf("ised: lift: %w", err)
	}
	if object == nil {
		return Program{}, fmt.Errorf("%w: nil object", ErrInvalidObject)
	}
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return Program{}, fmt.Errorf("%w: %s", ErrUnsupportedMachine, object.Machine)
	}
	if options.Disassembler != nil && options.NewDisassembler != nil {
		return Program{}, fmt.Errorf("%w: Disassembler and NewDisassembler are mutually exclusive", ErrInvalidObject)
	}
	text := object.GetSection(".text")
	if text == nil {
		return Program{}, fmt.Errorf("%w: object has no .text section", ErrInvalidObject)
	}
	if !text.IsExecutable() {
		return Program{}, fmt.Errorf("%w: .text is not executable", ErrInvalidObject)
	}
	if uint64(len(text.Data)) > math.MaxUint32 {
		return Program{}, fmt.Errorf("%w: .text exceeds the COFF address space", ErrInvalidObject)
	}

	mode := x86.Mode32
	if object.Machine == coff.MachineAMD64 {
		mode = x86.Mode64
	}
	decoder := options.Disassembler
	owned := false
	var err error
	if decoder == nil {
		factory := options.NewDisassembler
		if factory == nil {
			factory = func(ctx context.Context, mode x86.Mode) (x86.Disassembler, error) {
				return x86.NewCapstone(ctx, mode)
			}
		}
		decoder, err = factory(ctx, mode)
		if err != nil {
			return Program{}, fmt.Errorf("ised: open disassembler: %w", err)
		}
		if decoder == nil {
			return Program{}, fmt.Errorf("%w: disassembler factory returned nil", ErrInvalidObject)
		}
		owned = true
	}
	decoded, decodeErr := decoder.Disassemble(ctx, append([]byte(nil), text.Data...), 0)
	var closeErr error
	if owned {
		closeErr = decoder.Close(context.WithoutCancel(ctx))
	}
	if decodeErr != nil {
		if closeErr != nil {
			decodeErr = errors.Join(decodeErr, closeErr)
		}
		return Program{}, fmt.Errorf("ised: disassemble .text: %w", decodeErr)
	}
	if closeErr != nil {
		return Program{}, fmt.Errorf("ised: close disassembler: %w", closeErr)
	}

	labels, err := liftLabels(object, text)
	if err != nil {
		return Program{}, err
	}
	if len(text.Data) != 0 {
		if len(labels) == 0 {
			return Program{}, fmt.Errorf("%w: non-empty .text has no function or global-data symbol", ErrInvalidObject)
		}
		first := uint32(math.MaxUint32)
		for offset := range labels {
			if offset < first {
				first = offset
			}
		}
		if first != 0 {
			return Program{}, fmt.Errorf("%w: first .text code symbol starts at %#x, want zero", ErrInvalidObject, first)
		}
	}
	boundaries := make(map[uint32]struct{}, len(decoded)+1)
	boundaries[0] = struct{}{}
	var expected uint64
	for index, instruction := range decoded {
		if instruction.Address != expected || len(instruction.Bytes) == 0 {
			return Program{}, fmt.Errorf("%w: decoded instruction %d starts at %#x, want %#x", ErrInvalidObject, index, instruction.Address, expected)
		}
		end := expected + uint64(len(instruction.Bytes))
		if end > uint64(len(text.Data)) || !bytes.Equal(instruction.Bytes, text.Data[expected:end]) {
			return Program{}, fmt.Errorf("%w: decoded instruction at %#x exceeds or differs from .text", ErrInvalidObject, expected)
		}
		expected = end
		boundaries[uint32(end)] = struct{}{}
	}
	if expected != uint64(len(text.Data)) {
		return Program{}, fmt.Errorf("%w: disassembler consumed %d of %d .text bytes", ErrInvalidObject, expected, len(text.Data))
	}
	for offset, label := range labels {
		if offset < uint32(len(text.Data)) {
			if _, ok := boundaries[offset]; !ok {
				return Program{}, &BoundaryError{Function: label.name, Section: text.Name, Offset: offset, Feature: "symbol on an instruction interior", Err: ErrInvalidObject}
			}
		}
	}
	if err := validateLiftRelocations(object, text); err != nil {
		return Program{}, err
	}

	program := Program{Machine: object.Machine, Functions: make([]Function, 0)}
	var current *Function
	for _, decodedInstruction := range decoded {
		if err := ctx.Err(); err != nil {
			return Program{}, fmt.Errorf("ised: lift: %w", err)
		}
		offset := uint32(decodedInstruction.Address)
		if label, ok := labels[offset]; ok {
			current = nil
			if label.function {
				program.Functions = append(program.Functions, Function{Name: label.name, Section: text.Name})
				current = &program.Functions[len(program.Functions)-1]
			}
		}
		if current == nil {
			continue
		}
		semantic := decodeSemantic(object.Machine, offset, decodedInstruction, uint32(len(text.Data)), labels)
		for _, relocation := range text.Relocations {
			if relocation.VirtualAddress >= offset && uint64(relocation.VirtualAddress) < uint64(offset)+uint64(len(semantic.Bytes)) {
				semantic.HasRelocation = true
			}
		}
		semantic.PointerFix = pointerFix(semantic, options.ReturnAddress, labels)
		current.Instructions = append(current.Instructions, semantic)
	}
	for index := range program.Functions {
		analyzeFlagZones(&program.Functions[index])
		// RewritePass constructs Bookends with the x64 PrologueWalk. Preserve
		// that observable behavior; upstream unwind generation is x64-specific.
		if options.Unwind && object.Machine == coff.MachineAMD64 {
			markBookends(object.Machine, &program.Functions[index])
		}
	}
	return cloneProgram(program), nil
}

type liftedLabel struct {
	name     string
	function bool
}

func liftLabels(object *coff.Object, text *coff.Section) (map[uint32]liftedLabel, error) {
	labels := make(map[uint32]liftedLabel)
	for index, symbol := range object.Symbols {
		if symbol == nil {
			return nil, fmt.Errorf("%w: symbol %d is nil", ErrInvalidObject, index)
		}
		if symbol.Section != text || !symbol.IsFunction() && !symbol.IsGlobalVariable() {
			continue
		}
		if symbol.Name == "" {
			return nil, fmt.Errorf("%w: code symbol %d has an empty name", ErrInvalidObject, index)
		}
		if uint64(symbol.Value) > uint64(len(text.Data)) {
			return nil, fmt.Errorf("%w: code symbol %q at %#x is outside .text", ErrInvalidObject, symbol.Name, symbol.Value)
		}
		// Code.analyze() uses a map keyed by value. Later symbols win.
		labels[symbol.Value] = liftedLabel{name: symbol.Name, function: symbol.IsFunction()}
	}
	return labels, nil
}

func validateLiftRelocations(object *coff.Object, text *coff.Section) error {
	knownSymbols := make(map[*coff.Symbol]struct{}, len(object.Symbols))
	for _, symbol := range object.Symbols {
		if symbol != nil {
			knownSymbols[symbol] = struct{}{}
		}
	}
	for index, relocation := range text.Relocations {
		if relocation == nil {
			return fmt.Errorf("%w: .text relocation %d is nil", ErrInvalidObject, index)
		}
		if relocation.Section != nil && relocation.Section != text {
			return fmt.Errorf("%w: .text relocation %d has a foreign parent", ErrInvalidObject, index)
		}
		if relocation.Symbol != nil {
			if _, ok := knownSymbols[relocation.Symbol]; !ok {
				return fmt.Errorf("%w: .text relocation %d points to a foreign symbol", ErrInvalidObject, index)
			}
		}
		if uint64(relocation.VirtualAddress) >= uint64(len(text.Data)) {
			return fmt.Errorf("%w: .text relocation %d at %#x is outside the section", ErrInvalidObject, index, relocation.VirtualAddress)
		}
	}
	return nil
}

func pointerFix(instruction Instruction, returnAddress string, labels map[uint32]liftedLabel) bool {
	if returnAddress == "" {
		return false
	}
	if instruction.Form == "CALL rel32" {
		if instruction.PCRelativeUnknown {
			return false
		}
		label, ok := labels[instruction.RelativeTarget]
		return ok && label.name == returnAddress
	}
	return instruction.HasRelocation
}

func decodeSemantic(machine coff.Machine, offset uint32, decoded x86.Instruction, textSize uint32, labels map[uint32]liftedLabel) Instruction {
	result := Instruction{
		Offset: offset, Bytes: append([]byte(nil), decoded.Bytes...),
		Mnemonic: strings.ToUpper(strings.TrimSpace(decoded.Mnemonic)), Incomplete: true,
	}
	raw := result.Bytes
	position, rex, operand16, rep, ok := decodePrefixes(machine, raw)
	result.repPrefix = rep
	if !ok || position >= len(raw) {
		classifyFlags(&result)
		return result
	}
	opcodePosition := position
	legacyPrefixes := opcodePosition
	if rex != 0 {
		legacyPrefixes--
	}
	opcode := raw[position]
	position++
	bits := 32
	if machine == coff.MachineAMD64 && rex&8 != 0 {
		bits = 64
	}
	if operand16 {
		bits = 16
	}
	complete := func(form, assembly, mnemonic string) {
		result.Form, result.Assembly, result.Mnemonic = form, assembly, mnemonic
		result.Incomplete = false
	}
	partial := func(form, mnemonic string) {
		result.Form, result.Mnemonic, result.Incomplete = form, mnemonic, true
	}

	switch {
	case opcode == 0x90 && opcodePosition == 0 && len(raw) == 1:
		complete("NOP", "nop", "NOP")
	case opcode == 0xcc && opcodePosition == 0 && len(raw) == 1:
		complete("INT3", "int3", "INT3")
	case opcode == 0xc3 && opcodePosition == 0 && len(raw) == 1:
		complete("RET", "ret", "RET")
		result.controlFlow, result.unconditional = true, true
	case opcode == 0xc9 && opcodePosition == 0 && len(raw) == 1:
		complete("LEAVE", "leave", "LEAVE")
	case opcode >= 0x50 && opcode <= 0x57 && !operand16 && position == len(raw):
		register := int(opcode-0x50) + int(rex&1)*8
		width := 32
		if machine == coff.MachineAMD64 {
			width = 64
		}
		name := registerName(width, register)
		if name != "" {
			result.operand0 = name
			complete(fmt.Sprintf("PUSH r%d", width), "push "+name, "PUSH")
		}
	case opcode >= 0x58 && opcode <= 0x5f && !operand16 && position == len(raw):
		register := int(opcode-0x58) + int(rex&1)*8
		width := 32
		if machine == coff.MachineAMD64 {
			width = 64
		}
		name := registerName(width, register)
		if name != "" {
			result.operand0 = name
			complete(fmt.Sprintf("POP r%d", width), "pop "+name, "POP")
		}
	case opcode == 0x68 && position+4 == len(raw) && !operand16:
		partial("PUSH imm32", "PUSH")
	case opcode == 0x6a && position+1 == len(raw):
		partial("PUSH imm8", "PUSH")
	case opcode >= 0xb8 && opcode <= 0xbf:
		immediate := 4
		if bits == 64 {
			immediate = 8
		}
		if position+immediate == len(raw) {
			register := int(opcode-0xb8) + int(rex&1)*8
			result.operand0 = registerName(bits, register)
			partial(fmt.Sprintf("MOV r%d, imm%d", bits, immediate*8), "MOV")
		}
	case opcode == 0xe8 && position+4 == len(raw):
		partial("CALL rel32", "CALL")
		result.call, result.controlFlow = true, true
		setRelative(&result, position, 4, textSize)
		if !result.PCRelativeUnknown {
			_, result.RelativeTargetBefore = labels[result.RelativeTarget]
		}
	case opcode == 0xe9 && position+4 == len(raw):
		partial("JMP rel32", "JMP")
		result.controlFlow, result.unconditional = true, true
		setRelative(&result, position, 4, textSize)
		if !result.PCRelativeUnknown {
			_, result.RelativeTargetBefore = labels[result.RelativeTarget]
		}
	case opcode == 0xeb && position+1 == len(raw):
		partial("JMP rel8", "JMP")
		result.controlFlow, result.unconditional = true, true
		setRelative(&result, position, 1, textSize)
		if !result.PCRelativeUnknown {
			_, result.RelativeTargetBefore = labels[result.RelativeTarget]
		}
	case opcode >= 0x70 && opcode <= 0x7f && position+1 == len(raw):
		mnemonic := conditionMnemonic(opcode & 0x0f)
		partial(mnemonic+" rel8", mnemonic)
		result.controlFlow, result.readsFlags = true, true
		setRelative(&result, position, 1, textSize)
	case opcode >= 0xe0 && opcode <= 0xe3 && position+1 == len(raw):
		mnemonic := loopMnemonic(opcode, machine)
		partial(mnemonic+" rel8", mnemonic)
		result.controlFlow = true
		result.readsFlags = opcode == 0xe0 || opcode == 0xe1
		setRelative(&result, position, 1, textSize)
	case opcode == 0x0f && position < len(raw):
		second := raw[position]
		position++
		switch {
		case second >= 0x80 && second <= 0x8f && position+4 == len(raw):
			mnemonic := conditionMnemonic(second & 0x0f)
			partial(mnemonic+" rel32", mnemonic)
			result.controlFlow, result.readsFlags = true, true
			setRelative(&result, position, 4, textSize)
		case second == 0x0b && opcodePosition == 0 && len(raw) == 2:
			complete("UD2", "ud2", "UD2")
			result.controlFlow, result.unconditional = true, true
		case second == 0x1e && rep && position < len(raw) && raw[position] == 0xfa && position+1 == len(raw) && machine == coff.MachineAMD64:
			complete("ENDBR64", "endbr64", "ENDBR64")
			result.repPrefix = false
		}
	default:
		decodeModRMInstruction(machine, raw, position, opcode, bits, rex, textSize, &result)
	}
	if legacyPrefixes > 0 && result.Mnemonic != "ENDBR64" && result.Mnemonic != "ENDBR32" {
		// The opcode form remains useful, but the exact MASM spelling can expose
		// LOCK/REP/segment prefixes that the portable detail API does not model.
		result.Assembly, result.Incomplete = "", true
	}

	if result.Mnemonic != "" && !mnemonicsAgree(result.Mnemonic, decoded.Mnemonic) {
		result.Form, result.Assembly, result.Incomplete = "", "", true
		result.unknownFlags = true
	}
	if machine == coff.MachineAMD64 && operandMentionsIP(decoded.Operands) && !result.PCRelative {
		if field, ok := terminalRIPDisplacement(raw); ok {
			setRelative(&result, field, 4, textSize)
		}
		// The field location can make a relocation-backed copy safe, but the
		// unsupported opcode remains ineligible for unrelocated repair.
		result.PCRelativeUnknown = true
	}
	if result.relativeMemory && !result.PCRelativeUnknown {
		_, result.RelativeTargetBefore = labels[result.RelativeTarget]
	}
	if isRelativeMnemonic(result.Mnemonic) && !result.PCRelative && result.Mnemonic != "CALL" && result.Mnemonic != "JMP" {
		result.PCRelativeUnknown = true
	}
	classifyFlags(&result)
	return result
}

func decodePrefixes(machine coff.Machine, raw []byte) (position int, rex byte, operand16, rep, ok bool) {
	ok = true
	for position < len(raw) {
		switch raw[position] {
		case 0x66:
			operand16 = true
			position++
		case 0xf2, 0xf3:
			rep = true
			position++
		case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0xf0:
			position++
		case 0x67:
			// Address-size overrides are never interpreted semantically.
			return position + 1, rex, operand16, rep, false
		default:
			if machine == coff.MachineAMD64 && raw[position] >= 0x40 && raw[position] <= 0x4f {
				rex = raw[position]
				position++
				continue
			}
			return position, rex, operand16, rep, ok
		}
	}
	return position, rex, operand16, rep, ok
}

func decodeModRMInstruction(machine coff.Machine, raw []byte, position int, opcode byte, bits int, rex byte, textSize uint32, result *Instruction) {
	if position >= len(raw) {
		return
	}
	modRMPosition := position
	modRM := raw[position]
	position++
	mod, reg, rm := modRM>>6, int((modRM>>3)&7)+int((rex>>2)&1)*8, int(modRM&7)+int(rex&1)*8
	regName, rmName := registerName(bits, reg), registerName(bits, rm)
	setBinary := func(mnemonic, rmForm, regForm string) {
		if mod != 3 || position != len(raw) || regName == "" || rmName == "" {
			if form := modRMForm(opcode, bits); form != "" {
				result.Form, result.Mnemonic = form, mnemonic
			}
			return
		}
		form := rmForm
		destination, source := rmName, regName
		if regForm != "" {
			form, destination, source = regForm, regName, rmName
		}
		result.Form, result.Assembly, result.Mnemonic, result.Incomplete = form, strings.ToLower(mnemonic)+" "+destination+", "+source, mnemonic, false
		result.operand0, result.operand1 = destination, source
	}
	switch opcode {
	case 0x89:
		setBinary("MOV", fmt.Sprintf("MOV r/m%d, r%d", bits, bits), "")
	case 0x8b:
		setBinary("MOV", "", fmt.Sprintf("MOV r%d, r/m%d", bits, bits))
		if machine == coff.MachineAMD64 && bits == 64 {
			if field, ok := ripDisplacement(raw, modRMPosition); ok {
				setRelative(result, field, 4, textSize)
				result.relativeMemory = true
			}
		}
	case 0x01:
		setBinary("ADD", fmt.Sprintf("ADD r/m%d, r%d", bits, bits), "")
	case 0x03:
		setBinary("ADD", "", fmt.Sprintf("ADD r%d, r/m%d", bits, bits))
	case 0x29:
		setBinary("SUB", fmt.Sprintf("SUB r/m%d, r%d", bits, bits), "")
	case 0x2b:
		setBinary("SUB", "", fmt.Sprintf("SUB r%d, r/m%d", bits, bits))
	case 0x31:
		setBinary("XOR", fmt.Sprintf("XOR r/m%d, r%d", bits, bits), "")
	case 0x33:
		setBinary("XOR", "", fmt.Sprintf("XOR r%d, r/m%d", bits, bits))
	case 0x39:
		setBinary("CMP", fmt.Sprintf("CMP r/m%d, r%d", bits, bits), "")
	case 0x3b:
		setBinary("CMP", "", fmt.Sprintf("CMP r%d, r/m%d", bits, bits))
	case 0x85:
		setBinary("TEST", fmt.Sprintf("TEST r/m%d, r%d", bits, bits), "")
	case 0x81, 0x83:
		if mod != 3 {
			return
		}
		immediate := 4
		immediateName := "imm32"
		if opcode == 0x83 {
			immediate, immediateName = 1, "imm8"
		}
		if position+immediate != len(raw) {
			return
		}
		mnemonic := ""
		switch (modRM >> 3) & 7 {
		case 0:
			mnemonic = "ADD"
		case 5:
			mnemonic = "SUB"
		case 7:
			mnemonic = "CMP"
		}
		if mnemonic != "" {
			result.Form = fmt.Sprintf("%s r/m%d, %s", mnemonic, bits, immediateName)
			result.Mnemonic, result.operand0 = mnemonic, rmName
		}
	case 0x8d:
		if mod == 3 || machine != coff.MachineAMD64 || bits != 64 {
			return
		}
		result.Form, result.Mnemonic = "LEA r64, m", "LEA"
		result.operand0 = registerName(64, reg)
		result.memoryBase = decodeMemoryBase64(raw, modRMPosition, rex)
		if field, ok := ripDisplacement(raw, modRMPosition); ok {
			setRelative(result, field, 4, textSize)
			result.relativeMemory = true
		}
	case 0xff:
		group := (modRM >> 3) & 7
		width := 32
		if machine == coff.MachineAMD64 {
			width = 64
		}
		mnemonic := ""
		switch group {
		case 2:
			mnemonic, result.call, result.controlFlow = "CALL", true, true
		case 4:
			mnemonic, result.controlFlow, result.unconditional = "JMP", true, true
		case 6:
			mnemonic = "PUSH"
		}
		if mnemonic == "" {
			return
		}
		result.Form, result.Mnemonic = fmt.Sprintf("%s r/m%d", mnemonic, width), mnemonic
		if mod == 3 && position == len(raw) {
			name := registerName(width, rm)
			if name != "" {
				result.Assembly, result.Incomplete, result.operand0 = strings.ToLower(mnemonic)+" "+name, false, name
			}
		}
		if machine == coff.MachineAMD64 && group == 2 {
			if field, ok := ripDisplacement(raw, modRMPosition); ok {
				setRelative(result, field, 4, textSize)
				result.relativeMemory = true
			}
		}
	}
}

func modRMForm(opcode byte, bits int) string {
	switch opcode {
	case 0x89:
		return fmt.Sprintf("MOV r/m%d, r%d", bits, bits)
	case 0x8b:
		return fmt.Sprintf("MOV r%d, r/m%d", bits, bits)
	case 0x01:
		return fmt.Sprintf("ADD r/m%d, r%d", bits, bits)
	case 0x03:
		return fmt.Sprintf("ADD r%d, r/m%d", bits, bits)
	case 0x29:
		return fmt.Sprintf("SUB r/m%d, r%d", bits, bits)
	case 0x2b:
		return fmt.Sprintf("SUB r%d, r/m%d", bits, bits)
	case 0x31:
		return fmt.Sprintf("XOR r/m%d, r%d", bits, bits)
	case 0x33:
		return fmt.Sprintf("XOR r%d, r/m%d", bits, bits)
	case 0x39:
		return fmt.Sprintf("CMP r/m%d, r%d", bits, bits)
	case 0x3b:
		return fmt.Sprintf("CMP r%d, r/m%d", bits, bits)
	case 0x85:
		return fmt.Sprintf("TEST r/m%d, r%d", bits, bits)
	default:
		return ""
	}
}

func setRelative(result *Instruction, field, width int, textSize uint32) {
	if field < 0 || width != 1 && width != 4 || field+width > len(result.Bytes) {
		result.PCRelativeUnknown = true
		return
	}
	var displacement int64
	if width == 1 {
		displacement = int64(int8(result.Bytes[field]))
	} else {
		displacement = int64(int32(binary.LittleEndian.Uint32(result.Bytes[field : field+4])))
	}
	target := int64(result.Offset) + int64(len(result.Bytes)) + displacement
	result.PCRelative = true
	result.RelativeOffset, result.RelativeWidth = uint8(field), uint8(width)
	if target < 0 || target > int64(textSize) || target > math.MaxUint32 {
		result.PCRelativeUnknown = true
		return
	}
	result.RelativeTarget = uint32(target)
}

func ripDisplacement(raw []byte, modRMPosition int) (int, bool) {
	if modRMPosition < 0 || modRMPosition >= len(raw) {
		return 0, false
	}
	modRM := raw[modRMPosition]
	if modRM>>6 != 0 || modRM&7 != 5 || modRMPosition+5 != len(raw) {
		return 0, false
	}
	return modRMPosition + 1, true
}

func terminalRIPDisplacement(raw []byte) (int, bool) {
	if len(raw) < 6 {
		return 0, false
	}
	modRMPosition := len(raw) - 5
	modRM := raw[modRMPosition]
	if modRM>>6 != 0 || modRM&7 != 5 {
		return 0, false
	}
	return modRMPosition + 1, true
}

func decodeMemoryBase64(raw []byte, modRMPosition int, rex byte) string {
	if modRMPosition < 0 || modRMPosition >= len(raw) {
		return ""
	}
	modRM := raw[modRMPosition]
	if modRM>>6 == 3 {
		return ""
	}
	rm := modRM & 7
	if rm != 4 {
		if modRM>>6 == 0 && rm == 5 {
			return "rip"
		}
		return registerName(64, int(rm)+int(rex&1)*8)
	}
	if modRMPosition+1 >= len(raw) {
		return ""
	}
	sib := raw[modRMPosition+1]
	base := sib & 7
	if modRM>>6 == 0 && base == 5 {
		return ""
	}
	return registerName(64, int(base)+int(rex&1)*8)
}

func registerName(bits, index int) string {
	if index < 0 || index >= 16 || bits != 32 && bits != 64 {
		return ""
	}
	registers32 := [...]string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"}
	registers64 := [...]string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
	if bits == 32 {
		return registers32[index]
	}
	return registers64[index]
}

func conditionMnemonic(condition byte) string {
	return [...]string{"JO", "JNO", "JB", "JAE", "JE", "JNE", "JBE", "JA", "JS", "JNS", "JP", "JNP", "JL", "JGE", "JLE", "JG"}[condition&0x0f]
}

func loopMnemonic(opcode byte, machine coff.Machine) string {
	switch opcode {
	case 0xe0:
		return "LOOPNE"
	case 0xe1:
		return "LOOPE"
	case 0xe2:
		return "LOOP"
	case 0xe3:
		if machine == coff.MachineAMD64 {
			return "JRCXZ"
		}
		return "JECXZ"
	default:
		return ""
	}
}

func mnemonicsAgree(expected, actual string) bool {
	expected, actual = strings.ToUpper(expected), strings.ToUpper(strings.TrimSpace(actual))
	aliases := map[string]string{"JZ": "JE", "JNZ": "JNE", "JC": "JB", "JNC": "JAE", "JNAE": "JB", "JNB": "JAE", "JNA": "JBE", "JNBE": "JA", "JPE": "JP", "JPO": "JNP", "JNGE": "JL", "JNL": "JGE", "JNG": "JLE", "JNLE": "JG"}
	if alias := aliases[actual]; alias != "" {
		actual = alias
	}
	return expected == actual
}

func operandMentionsIP(operands string) bool {
	for _, token := range strings.FieldsFunc(strings.ToLower(operands), func(value rune) bool {
		return !(value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '_')
	}) {
		if token == "rip" || token == "eip" {
			return true
		}
	}
	return false
}

func isRelativeMnemonic(mnemonic string) bool {
	return strings.HasPrefix(mnemonic, "J") || strings.HasPrefix(mnemonic, "LOOP")
}

func classifyFlags(instruction *Instruction) {
	if instruction.writesFlags || instruction.readsFlags || instruction.unknownFlags {
		return
	}
	mnemonic := strings.ToUpper(instruction.Mnemonic)
	switch {
	case mnemonic == "ADD" || mnemonic == "SUB" || mnemonic == "AND" || mnemonic == "OR" || mnemonic == "XOR" || mnemonic == "CMP" || mnemonic == "TEST" || mnemonic == "INC" || mnemonic == "DEC" || mnemonic == "NEG" || mnemonic == "SHL" || mnemonic == "SAL" || mnemonic == "SHR" || mnemonic == "SAR" || mnemonic == "ROL" || mnemonic == "ROR" || mnemonic == "IMUL" || mnemonic == "MUL" || mnemonic == "CLC" || mnemonic == "STC" || mnemonic == "CMC" || mnemonic == "CLD" || mnemonic == "STD":
		instruction.writesFlags = true
	case mnemonic == "ADC" || mnemonic == "SBB" || mnemonic == "RCL" || mnemonic == "RCR":
		instruction.writesFlags, instruction.readsFlags = true, true
	case strings.HasPrefix(mnemonic, "J") && mnemonic != "JMP" && mnemonic != "JCXZ" && mnemonic != "JECXZ" && mnemonic != "JRCXZ" || strings.HasPrefix(mnemonic, "CMOV") || strings.HasPrefix(mnemonic, "SET") || mnemonic == "LAHF" || mnemonic == "PUSHF" || mnemonic == "PUSHFD" || mnemonic == "PUSHFQ":
		instruction.readsFlags = true
	case mnemonic == "" || mnemonic == "INVALID":
		instruction.unknownFlags = true
	case mnemonic == "MOV" || mnemonic == "MOVZX" || mnemonic == "MOVSX" || mnemonic == "MOVSXD" || mnemonic == "LEA" || mnemonic == "PUSH" || mnemonic == "POP" || mnemonic == "NOP" || mnemonic == "CALL" || mnemonic == "JMP" || mnemonic == "RET" || mnemonic == "LEAVE" || mnemonic == "INT3" || mnemonic == "UD2" || mnemonic == "ENDBR32" || mnemonic == "ENDBR64" || mnemonic == "XCHG" || mnemonic == "CDQ" || mnemonic == "CDQE" || mnemonic == "CQO" || mnemonic == "LOOP" || mnemonic == "JCXZ" || mnemonic == "JECXZ" || mnemonic == "JRCXZ":
		// Proven not to establish or consume an ordinary flag dependency.
	default:
		instruction.unknownFlags = true
	}
}

func analyzeFlagZones(function *Function) {
	if function == nil || len(function.Instructions) == 0 {
		return
	}
	for index := range function.Instructions {
		if function.Instructions[index].unknownFlags {
			taintFunction(function)
			return
		}
	}
	leaders := map[int]struct{}{0: {}}
	byOffset := make(map[uint32]int, len(function.Instructions))
	for index, instruction := range function.Instructions {
		byOffset[instruction.Offset] = index
	}
	for index, instruction := range function.Instructions {
		if instruction.PCRelative {
			if target, ok := byOffset[instruction.RelativeTarget]; ok {
				leaders[target] = struct{}{}
			}
		}
		if instruction.controlFlow && !instruction.call && index+1 < len(function.Instructions) {
			leaders[index+1] = struct{}{}
		}
	}
	starts := make([]int, 0, len(leaders))
	for start := range leaders {
		starts = append(starts, start)
	}
	sort.Ints(starts)
	for blockIndex, start := range starts {
		end := len(function.Instructions)
		if blockIndex+1 < len(starts) {
			end = starts[blockIndex+1]
		}
		for consumer := start; consumer < end; consumer++ {
			if !function.Instructions[consumer].readsFlags || function.Instructions[consumer].repPrefix {
				continue
			}
			function.Instructions[consumer].FlagConsumer = true
			found := false
			for previous := consumer - 1; previous >= start; previous-- {
				candidate := &function.Instructions[previous]
				if candidate.repPrefix {
					candidate.DangerZone = true
					continue
				}
				if candidate.writesFlags {
					candidate.FlagProducer = true
					found = true
					break
				}
				candidate.DangerZone = true
			}
			if !found {
				taintFunction(function)
				return
			}
		}
	}
}

func taintFunction(function *Function) {
	for index := range function.Instructions {
		if !function.Instructions[index].call {
			function.Instructions[index].DangerZone = true
		}
	}
}

func markBookends(machine coff.Machine, function *Function) {
	if function == nil || len(function.Instructions) == 0 {
		return
	}
	instructions := function.Instructions
	cursor := 0
	for cursor < len(instructions) {
		instruction := &instructions[cursor]
		cursor++ // Java's ListIterator consumes the first non-prologue too.
		if machine == coff.MachineAMD64 {
			switch {
			case instruction.Form == "PUSH r64":
				instruction.Bookend = true
				continue
			case (instruction.Form == "SUB r/m64, imm8" || instruction.Form == "SUB r/m64, imm32") && instruction.operand0 == "rsp":
				instruction.Bookend = true
				continue
			case instruction.Form == "MOV r/m64, r64" && instruction.operand1 == "rsp":
				instruction.Bookend = true
			case instruction.Form == "LEA r64, m" && instruction.memoryBase == "rsp":
				instruction.Bookend = true
			}
		} else if instruction.Form == "PUSH r32" {
			instruction.Bookend = true
			continue
		}
		break
	}
	for ; cursor < len(instructions); cursor++ {
		instruction := &instructions[cursor]
		exit := instruction.Form == "RET"
		if machine == coff.MachineAMD64 && instruction.Form == "JMP r/m64" && instruction.operand0 == "rcx" {
			exit = true
		}
		if !exit {
			continue
		}
		instruction.Bookend = true
		for previous := cursor - 1; previous >= 0; previous-- {
			candidate := &instructions[previous]
			if machine == coff.MachineAMD64 {
				if candidate.Form == "POP r64" || (candidate.Form == "ADD r/m64, imm8" || candidate.Form == "ADD r/m64, imm32") && candidate.operand0 == "rsp" {
					candidate.Bookend = true
					continue
				}
			} else if candidate.Form == "POP r32" {
				candidate.Bookend = true
				continue
			}
			break
		}
		return
	}
}
