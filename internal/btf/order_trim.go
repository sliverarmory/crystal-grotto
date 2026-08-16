// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package btf

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

// ErrReferencedOptimizedPadding reports that +optimize found terminal
// NOP/INT3 instructions but could not remove them without invalidating a
// surviving symbol, relocation, or decoded position-dependent reference.
var ErrReferencedOptimizedPadding = errors.New("btf: optimized padding is still referenced")

// ReferencedOptimizedPaddingError identifies the retained function and byte
// offset that made upstream-equivalent padding removal unsafe.
type ReferencedOptimizedPaddingError struct {
	Function string
	Target   uint32
	Source   string
}

func (e *ReferencedOptimizedPaddingError) Error() string {
	return fmt.Sprintf("%v: %s terminal padding at .text+%#x is required by %s", ErrReferencedOptimizedPadding, e.Function, e.Target, e.Source)
}

func (e *ReferencedOptimizedPaddingError) Unwrap() error { return ErrReferencedOptimizedPadding }

type paddingTrim struct {
	chunk *codeChunk
	start uint32
	end   uint32
}

func trimOptimizedPadding(object *coff.Object, text *coff.Section, kept []*codeChunk, analysis *orderAnalysis) error {
	if analysis == nil {
		return nil
	}
	trims := make(map[*codeChunk]paddingTrim)
	for _, chunk := range kept {
		if !chunk.isFunction() {
			continue
		}
		instructions := analysis.instructions[chunk]
		trimStart := chunk.end
		for index := len(instructions) - 1; index >= 0; index-- {
			instruction := instructions[index]
			if !isUpstreamOptimizePadding(instruction) {
				break
			}
			trimStart = instruction.start
		}
		if trimStart < chunk.end {
			trims[chunk] = paddingTrim{chunk: chunk, start: trimStart, end: chunk.end}
		}
	}
	if len(trims) == 0 {
		return nil
	}
	keptSet := make(map[*codeChunk]struct{}, len(kept))
	for _, chunk := range kept {
		keptSet[chunk] = struct{}{}
	}

	for _, symbol := range object.Symbols {
		if symbol == nil || symbol.Section != text || symbol.IsSectionName() {
			continue
		}
		if trim := trimAtOffset(trims, symbol.Value); trim != nil {
			return referencedPadding(trim, symbol.Value, fmt.Sprintf("COFF symbol %s", symbol.Name))
		}
	}
	for _, reference := range analysis.references {
		if _, sourceKept := keptSet[reference.source]; !sourceKept || sourceIsTrimmed(reference, trims) {
			continue
		}
		if trim := trimAtOffset(trims, reference.target); trim != nil {
			return referencedPadding(trim, reference.target, fmt.Sprintf("%s at .text+%#x", reference.description, reference.instructionStart))
		}
	}
	for _, section := range object.Sections {
		for _, relocation := range section.Relocations {
			if relocation == nil || relocationSourceRemoved(relocation, kept, trims) {
				continue
			}
			target, local, err := relocationTextTarget(text, relocation)
			if err != nil {
				return err
			}
			if !local {
				continue
			}
			if trim := trimAtOffset(trims, target); trim != nil {
				source := fmt.Sprintf("relocation in %s at %#x", section.Name, relocation.VirtualAddress)
				return referencedPadding(trim, target, source)
			}
		}
	}

	// Trims affect only private chunk copies. The COFF graph remains untouched
	// until rebuildText completes every later validation and reference repair.
	for chunk, trim := range trims {
		chunk.data = chunk.data[:trim.start-chunk.start]
	}
	return nil
}

// CodeUtils.is() compares Iced's complete opcode instruction string. "NOP"
// therefore means the zero-operand 90 form (prefixes are allowed), not the
// operand-bearing 0F 1F /0 family whose instruction string is "NOP r/m*".
func isUpstreamOptimizePadding(instruction *decodedOrderInstruction) bool {
	if instruction == nil {
		return false
	}
	if instruction.mnemonic == "int3" {
		return true
	}
	if instruction.mnemonic != "nop" || len(instruction.raw) == 0 || instruction.raw[len(instruction.raw)-1] != 0x90 {
		return false
	}
	for _, prefix := range instruction.raw[:len(instruction.raw)-1] {
		if !isOrderLegacyPrefix(prefix) && (prefix < 0x40 || prefix > 0x4f) {
			return false
		}
	}
	return true
}

func sourceIsTrimmed(reference orderReference, trims map[*codeChunk]paddingTrim) bool {
	trim, trimmed := trims[reference.source]
	return trimmed && reference.instructionStart >= trim.start
}

func relocationSourceRemoved(relocation *coff.Relocation, kept []*codeChunk, trims map[*codeChunk]paddingTrim) bool {
	if relocation.Section == nil || relocation.Section.Name != ".text" {
		return false
	}
	source := chunkAtOffset(kept, relocation.VirtualAddress)
	if source == nil {
		return true
	}
	trim, trimmed := trims[source]
	return trimmed && relocation.VirtualAddress >= trim.start
}

func relocationTextTarget(text *coff.Section, relocation *coff.Relocation) (uint32, bool, error) {
	if relocation.Symbol == nil || relocation.Symbol.Section != text {
		return 0, false, nil
	}
	offset, err := relocation.Offset()
	if err != nil {
		return 0, false, fmt.Errorf("btf: inspect relocation at %#x for optimized padding: %w", relocation.VirtualAddress, err)
	}
	target := int64(relocation.Symbol.Value) + int64(offset)
	if target < 0 || target >= int64(len(text.Data)) {
		return 0, false, nil
	}
	return uint32(target), true, nil
}

func trimAtOffset(trims map[*codeChunk]paddingTrim, offset uint32) *paddingTrim {
	for _, candidate := range trims {
		if offset >= candidate.start && offset < candidate.end {
			trim := candidate
			return &trim
		}
	}
	return nil
}

func referencedPadding(trim *paddingTrim, target uint32, source string) error {
	return &ReferencedOptimizedPaddingError{
		Function: trim.chunk.displayName(),
		Target:   target,
		Source:   source,
	}
}

func optimizedFunctionAuxiliary(chunks []*codeChunk) (map[*coff.Symbol][][]byte, error) {
	updates := make(map[*coff.Symbol][][]byte)
	for _, chunk := range chunks {
		if uint32(len(chunk.data)) == chunk.end-chunk.start {
			continue
		}
		for _, symbol := range chunk.symbols {
			if !symbol.IsFunction() || len(symbol.AuxiliaryRecords) == 0 {
				continue
			}
			if len(symbol.AuxiliaryRecords[0]) != 18 {
				return nil, fmt.Errorf("btf: function %q has malformed auxiliary record during padding trim", symbol.Name)
			}
			records := make([][]byte, len(symbol.AuxiliaryRecords))
			for index, record := range symbol.AuxiliaryRecords {
				records[index] = append([]byte(nil), record...)
			}
			binary.LittleEndian.PutUint32(records[0][4:8], uint32(len(chunk.data)))
			updates[symbol] = records
		}
	}
	return updates, nil
}
