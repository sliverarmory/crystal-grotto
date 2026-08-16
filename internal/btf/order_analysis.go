// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package btf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

// ErrUnprovenOrderReference identifies code whose position-dependent target
// cannot be proved with the portable decoder. Ordering fails closed rather
// than emitting silently corrupted code.
var ErrUnprovenOrderReference = errors.New("btf: unproven ordering reference")

// UnprovenOrderReferenceError locates a position-dependent instruction that
// prevents a safe +gofirst, +optimize, or +disco transformation.
type UnprovenOrderReferenceError struct {
	Function string
	Offset   uint32
	Bytes    []byte
	Reason   string
}

func (e *UnprovenOrderReferenceError) Error() string {
	where := fmt.Sprintf("at .text+%#x", e.Offset)
	if e.Function != "" {
		where = fmt.Sprintf("in %s at .text+%#x", e.Function, e.Offset)
	}
	return fmt.Sprintf("%v %s (%x): %s", ErrUnprovenOrderReference, where, e.Bytes, e.Reason)
}

func (e *UnprovenOrderReferenceError) Unwrap() error { return ErrUnprovenOrderReference }

type orderAnalysis struct {
	edges        map[*codeChunk]map[*codeChunk]struct{}
	references   []orderReference
	instructions map[*codeChunk][]*decodedOrderInstruction
}

type orderReference struct {
	source           *codeChunk
	instructionStart uint32
	instructionEnd   uint32
	fieldOffset      uint32
	fieldSize        uint8
	target           uint32
	description      string
}

type decodedOrderInstruction struct {
	chunk    *codeChunk
	start    uint32
	end      uint32
	raw      []byte
	mnemonic string
	operands string
}

func analyzeOrder(object *coff.Object, text *coff.Section, chunks []*codeChunk, options OrderOptions) (*orderAnalysis, error) {
	result := &orderAnalysis{
		edges:        make(map[*codeChunk]map[*codeChunk]struct{}, len(chunks)),
		instructions: make(map[*codeChunk][]*decodedOrderInstruction, len(chunks)),
	}
	if len(text.Data) == 0 || (!options.GoFirst && !options.Optimize && !options.Disco) {
		return result, nil
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("btf: analyze ordering: %w", err)
	}
	decoder := options.Disassembler
	owned := false
	if decoder == nil {
		mode := x86.Mode64
		if object.IsX86() {
			mode = x86.Mode32
		}
		opened, err := x86.NewCapstone(ctx, mode)
		if err != nil {
			return nil, fmt.Errorf("btf: open ordering decoder: %w", err)
		}
		decoder, owned = opened, true
	}
	instructions, err := decodeOrderFunctions(ctx, decoder, chunks)
	if owned {
		if closeErr := decoder.Close(context.Background()); err == nil && closeErr != nil {
			err = fmt.Errorf("btf: close ordering decoder: %w", closeErr)
		}
	}
	if err != nil {
		return nil, err
	}
	boundaries := make(map[uint32]*decodedOrderInstruction, len(instructions))
	for _, instruction := range instructions {
		boundaries[instruction.start] = instruction
		result.instructions[instruction.chunk] = append(result.instructions[instruction.chunk], instruction)
	}
	symbolOffsets := make(map[uint32]struct{})
	for _, symbol := range object.Symbols {
		if symbol != nil && symbol.Section == text && !symbol.IsSectionName() {
			symbolOffsets[symbol.Value] = struct{}{}
		}
	}

	for _, instruction := range instructions {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("btf: analyze ordering: %w", err)
		}
		relative, hasRelative := decodeOrderRelative(instruction.raw)
		if hasRelative {
			field := instruction.start + uint32(relative.offset)
			covered, err := orderFieldRelocated(instruction, field, relative.size)
			if err != nil {
				return nil, err
			}
			if !covered {
				target, err := orderRelativeTarget(instruction, relative)
				if err != nil {
					return nil, unsupportedOrder(instruction, err.Error())
				}
				if target < 0 || target >= int64(len(text.Data)) {
					return nil, unsupportedOrder(instruction, "relative control flow targets outside .text without a relocation")
				}
				targetOffset := uint32(target)
				if boundaries[targetOffset] == nil {
					return nil, unsupportedOrder(instruction, fmt.Sprintf("relative target %#x is not a decoded instruction boundary", targetOffset))
				}
				targetChunk := chunkAtOffset(chunks, targetOffset)
				if targetChunk == nil || !targetChunk.isFunction() {
					return nil, unsupportedOrder(instruction, fmt.Sprintf("relative target %#x is not proven code", targetOffset))
				}
				result.addEdge(instruction.chunk, targetChunk)
				result.references = append(result.references, orderReference{
					source: instruction.chunk, instructionStart: instruction.start, instructionEnd: instruction.end,
					fieldOffset: field, fieldSize: uint8(relative.size), target: targetOffset, description: "relative branch",
				})
			}
		} else if isUnprovenOrderControlFlow(instruction) {
			return nil, unsupportedOrder(instruction, "direct control-flow form is not exposed by go-capstone and is not a supported raw encoding")
		}

		if object.IsX64() && hasOrderWord(instruction.operands, "rip") {
			displacementOffset, target, err := decodeOrderRIPRelative(instruction)
			if err != nil {
				return nil, unsupportedOrder(instruction, err.Error())
			}
			field := instruction.start + uint32(displacementOffset)
			covered, err := orderFieldRelocated(instruction, field, 4)
			if err != nil {
				return nil, err
			}
			if covered {
				continue
			}
			if target < 0 || target >= int64(len(text.Data)) {
				return nil, unsupportedOrder(instruction, "RIP-relative reference targets outside .text without a relocation")
			}
			targetOffset := uint32(target)
			if _, proven := symbolOffsets[targetOffset]; !proven {
				return nil, unsupportedOrder(instruction, fmt.Sprintf("RIP-relative target %#x has no local COFF symbol", targetOffset))
			}
			targetChunk := chunkAtOffset(chunks, targetOffset)
			if targetChunk == nil {
				return nil, unsupportedOrder(instruction, fmt.Sprintf("RIP-relative target %#x has no code chunk", targetOffset))
			}
			result.addEdge(instruction.chunk, targetChunk)
			result.references = append(result.references, orderReference{
				source: instruction.chunk, instructionStart: instruction.start, instructionEnd: instruction.end,
				fieldOffset: field, fieldSize: 4, target: targetOffset, description: "RIP-relative reference",
			})
		}
	}
	return result, nil
}

func decodeOrderFunctions(ctx context.Context, decoder x86.Disassembler, chunks []*codeChunk) ([]*decodedOrderInstruction, error) {
	var result []*decodedOrderInstruction
	for _, chunk := range chunks {
		if !chunk.isFunction() {
			continue
		}
		decoded, err := decoder.Disassemble(ctx, chunk.data, uint64(chunk.start))
		if err != nil {
			return nil, fmt.Errorf("btf: decode %s: %w", chunk.displayName(), err)
		}
		expected := chunk.start
		for _, raw := range decoded {
			if raw.Address > math.MaxUint32 || len(raw.Bytes) == 0 || uint64(len(raw.Bytes)) > math.MaxUint32-raw.Address {
				return nil, fmt.Errorf("btf: decoder returned out-of-range instruction for %s", chunk.displayName())
			}
			start := uint32(raw.Address)
			end := start + uint32(len(raw.Bytes))
			if start != expected || start < chunk.start || end > chunk.end {
				return nil, fmt.Errorf("btf: decoder returned non-contiguous instruction [%#x,%#x) for %s [%#x,%#x), expected %#x", start, end, chunk.displayName(), chunk.start, chunk.end, expected)
			}
			result = append(result, &decodedOrderInstruction{
				chunk: chunk, start: start, end: end, raw: append([]byte(nil), raw.Bytes...),
				mnemonic: strings.ToLower(raw.Mnemonic), operands: strings.ToLower(raw.Operands),
			})
			expected = end
		}
		if expected != chunk.end {
			return nil, fmt.Errorf("btf: decoder consumed through %#x of %s, want %#x", expected, chunk.displayName(), chunk.end)
		}
	}
	return result, nil
}

func (a *orderAnalysis) addEdge(source, target *codeChunk) {
	if source == nil || target == nil {
		return
	}
	if a.edges[source] == nil {
		a.edges[source] = make(map[*codeChunk]struct{})
	}
	a.edges[source][target] = struct{}{}
}

func orderFieldRelocated(instruction *decodedOrderInstruction, field uint32, size int) (bool, error) {
	fieldEnd := uint64(field) + uint64(size)
	for _, relocation := range instruction.chunk.relocs {
		patchStart := uint64(relocation.VirtualAddress)
		patchEnd := patchStart + 4
		if relocation.VirtualAddress == field && size == 4 {
			machine := coff.Machine(0)
			if relocation.Section != nil && relocation.Section.Object != nil {
				machine = relocation.Section.Object.Machine
			}
			if (machine == coff.MachineAMD64 && relocation.IsAMD64Rel32()) ||
				(machine == coff.MachineI386 && relocation.Type == coff.RelI386Rel32) {
				return true, nil
			}
			return false, unsupportedOrder(instruction, fmt.Sprintf("relocation type %#x does not prove a relative displacement", relocation.Type))
		}
		if patchStart < uint64(instruction.end) && patchEnd > uint64(instruction.start) ||
			uint64(field) < patchEnd && fieldEnd > patchStart {
			return false, unsupportedOrder(instruction, fmt.Sprintf("relocation at %#x does not exactly cover the position-dependent field at %#x", relocation.VirtualAddress, field))
		}
	}
	return false, nil
}

func unsupportedOrder(instruction *decodedOrderInstruction, reason string) error {
	function := ""
	if instruction != nil && instruction.chunk != nil {
		function = instruction.chunk.displayName()
	}
	result := &UnprovenOrderReferenceError{Function: function, Reason: reason}
	if instruction != nil {
		result.Offset = instruction.start
		result.Bytes = append([]byte(nil), instruction.raw...)
	}
	return result
}

func repairOrderReferences(output []byte, placements map[*codeChunk]uint32, analysis *orderAnalysis) error {
	if analysis == nil {
		return nil
	}
	for _, reference := range analysis.references {
		newChunkStart, sourceKept := placements[reference.source]
		if !sourceKept {
			continue
		}
		retainedEnd := reference.source.start + uint32(len(reference.source.data))
		if reference.instructionStart >= retainedEnd {
			continue
		}
		if reference.instructionEnd > retainedEnd {
			return fmt.Errorf("btf: %s at %#x straddles optimized padding", reference.description, reference.instructionStart)
		}
		newTarget, err := mapOrderOffset(reference.target, placements)
		if err != nil {
			return fmt.Errorf("btf: %s at %#x: %w", reference.description, reference.instructionStart, err)
		}
		newInstructionStart := newChunkStart + (reference.instructionStart - reference.source.start)
		instructionLength := reference.instructionEnd - reference.instructionStart
		newInstructionEnd := newInstructionStart + instructionLength
		displacement := int64(newTarget) - int64(newInstructionEnd)
		field := newInstructionStart + (reference.fieldOffset - reference.instructionStart)
		if uint64(field)+uint64(reference.fieldSize) > uint64(len(output)) {
			return fmt.Errorf("btf: %s field at %#x is outside rebuilt .text", reference.description, field)
		}
		switch reference.fieldSize {
		case 1:
			if displacement < math.MinInt8 || displacement > math.MaxInt8 {
				return fmt.Errorf("btf: %s at %#x overflows rel8 after ordering", reference.description, reference.instructionStart)
			}
			output[field] = byte(int8(displacement))
		case 4:
			if displacement < math.MinInt32 || displacement > math.MaxInt32 {
				return fmt.Errorf("btf: %s at %#x overflows rel32 after ordering", reference.description, reference.instructionStart)
			}
			binary.LittleEndian.PutUint32(output[field:field+4], uint32(int32(displacement)))
		default:
			return fmt.Errorf("btf: unsupported %s displacement width %d", reference.description, reference.fieldSize)
		}
	}
	return nil
}

func mapOrderOffset(old uint32, placements map[*codeChunk]uint32) (uint32, error) {
	for chunk, start := range placements {
		if old >= chunk.start && old < chunk.start+uint32(len(chunk.data)) {
			return start + (old - chunk.start), nil
		}
	}
	return 0, fmt.Errorf("target %#x was removed by ordering", old)
}

func chunkAtOffset(chunks []*codeChunk, offset uint32) *codeChunk {
	// The slice is deliberately reordered by +gofirst/+disco while start/end
	// retain original offsets, so this lookup must not assume slice ordering.
	for _, chunk := range chunks {
		if offset >= chunk.start && offset < chunk.end {
			return chunk
		}
	}
	return nil
}
