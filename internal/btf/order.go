// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

// Package btf implements binary transform framework passes over COFF code.
package btf

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

// OrderOptions controls symbol-, relocation-, and control-flow-safe function
// ordering. Relocation-free local branches are decoded and re-encoded when
// their source or target moves.
type OrderOptions struct {
	// Context controls decoding. A nil context is treated as Background.
	Context context.Context
	// Disassembler overrides the default portable Capstone decoder. The caller
	// retains ownership and ApplyOrderPasses never closes it.
	Disassembler x86.Disassembler

	Entry         string
	Exports       []string
	CatchHandlers []string
	GoFirst       bool
	Optimize      bool
	Disco         bool
	PreserveFirst bool
	Random        io.Reader
}

// OrderReport describes observable changes made by ApplyOrderPasses.
type OrderReport struct {
	OriginalOrder []string
	FinalOrder    []string
	Removed       []string
}

type codeChunk struct {
	start   uint32
	end     uint32
	data    []byte
	symbols []*coff.Symbol
	relocs  []*coff.Relocation
}

func (c *codeChunk) functionNames() []string {
	var result []string
	for _, symbol := range c.symbols {
		if symbol.IsFunction() {
			result = append(result, symbol.Name)
		}
	}
	return result
}

func (c *codeChunk) displayName() string {
	if functions := c.functionNames(); len(functions) != 0 {
		return functions[0]
	}
	for _, symbol := range c.symbols {
		if symbol.IsGlobalVariable() {
			return symbol.Name
		}
	}
	return fmt.Sprintf("<data@%#x>", c.start)
}

func (c *codeChunk) isFunction() bool { return len(c.functionNames()) != 0 }

// ApplyOrderPasses applies +gofirst, +optimize, and +disco in upstream order.
// It mutates object only after all validation and reachability checks succeed.
func ApplyOrderPasses(object *coff.Object, options OrderOptions) (OrderReport, error) {
	if object == nil {
		return OrderReport{}, errors.New("btf: nil COFF object")
	}
	text := object.GetSection(".text")
	if text == nil {
		return OrderReport{}, errors.New("btf: object has no .text section")
	}
	if !object.IsIntel() {
		return OrderReport{}, fmt.Errorf("btf: ordering is unsupported for %s", object.Machine)
	}
	chunks, err := splitCode(object, text)
	if err != nil {
		return OrderReport{}, err
	}
	report := OrderReport{OriginalOrder: chunkNames(chunks)}
	entry := options.Entry
	if entry == "" {
		if object.IsX86() {
			entry = "_go"
		} else {
			entry = "go"
		}
	}
	analysis, err := analyzeOrder(object, text, chunks, options)
	if err != nil {
		return OrderReport{}, err
	}
	removeSymbols := make(map[string]struct{})

	if options.GoFirst {
		index := chunkForFunction(chunks, entry)
		if index < 0 {
			return OrderReport{}, fmt.Errorf("+gofirst requires %s function as entrypoint", entry)
		}
		chunks = moveFirst(chunks, index)
	}
	if options.Optimize {
		var removed []string
		chunks, removed, removeSymbols, err = optimizeChunks(text, chunks, analysis, entry, options.Exports, options.CatchHandlers)
		if err != nil {
			return OrderReport{}, err
		}
		if err := trimOptimizedPadding(object, text, chunks, analysis); err != nil {
			return OrderReport{}, err
		}
		report.Removed = removed
	}
	if options.Disco {
		random := options.Random
		if random == nil {
			random = rand.Reader
		}
		if err := shuffleChunks(chunks, options.PreserveFirst, random); err != nil {
			return OrderReport{}, err
		}
	}
	if err := rebuildText(object, text, chunks, analysis, removeSymbols); err != nil {
		return OrderReport{}, err
	}
	report.FinalOrder = chunkNames(chunks)
	sort.Strings(report.Removed)
	return report, nil
}

func splitCode(object *coff.Object, text *coff.Section) ([]*codeChunk, error) {
	length := uint32(len(text.Data))
	boundaries := []uint32{0, length}
	for _, symbol := range object.Symbols {
		if symbol.Section != text || (!symbol.IsFunction() && !symbol.IsGlobalVariable()) {
			continue
		}
		if symbol.Value > length {
			return nil, fmt.Errorf("btf: symbol %s at %#x is outside .text", symbol.Name, symbol.Value)
		}
		boundaries = append(boundaries, symbol.Value)
	}
	sort.Slice(boundaries, func(i, j int) bool { return boundaries[i] < boundaries[j] })
	unique := boundaries[:0]
	for _, value := range boundaries {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	chunks := make([]*codeChunk, 0, len(unique)-1)
	for index := 0; index+1 < len(unique); index++ {
		start, end := unique[index], unique[index+1]
		if start == end {
			continue
		}
		chunk := &codeChunk{start: start, end: end, data: append([]byte(nil), text.Data[start:end]...)}
		for _, symbol := range object.Symbols {
			if symbol.Section == text && symbol.Value >= start && symbol.Value < end {
				chunk.symbols = append(chunk.symbols, symbol)
			}
		}
		for _, relocation := range text.Relocations {
			if relocation.VirtualAddress >= start && relocation.VirtualAddress < end {
				chunk.relocs = append(chunk.relocs, relocation)
			}
		}
		chunks = append(chunks, chunk)
	}
	if len(text.Data) == 0 {
		return []*codeChunk{}, nil
	}
	if len(chunks) == 0 {
		return nil, errors.New("btf: could not partition non-empty .text")
	}
	return chunks, nil
}

func optimizeChunks(text *coff.Section, chunks []*codeChunk, analysis *orderAnalysis, entry string, exports, handlers []string) ([]*codeChunk, []string, map[string]struct{}, error) {
	byFunction := make(map[string]*codeChunk)
	for _, chunk := range chunks {
		for _, name := range chunk.functionNames() {
			byFunction[name] = chunk
		}
	}
	seeds := append([]string{entry}, exports...)
	seeds = append(seeds, handlers...)
	reachable := make(map[*codeChunk]bool)
	var visit func(*codeChunk)
	visit = func(chunk *codeChunk) {
		if chunk == nil || reachable[chunk] {
			return
		}
		reachable[chunk] = true
		for target := range analysis.edges[chunk] {
			visit(target)
		}
		for _, relocation := range chunk.relocs {
			if strings.HasPrefix(relocation.SymbolName, ".refptr.") {
				visit(byFunction[strings.TrimPrefix(relocation.SymbolName, ".refptr.")])
				continue
			}
			if target := relocationTargetChunk(text, chunks, relocation); target != nil {
				visit(target)
			}
		}
	}
	roots := 0
	for _, seed := range seeds {
		if root := byFunction[seed]; root != nil {
			roots++
			visit(root)
		}
	}
	if roots == 0 {
		return nil, nil, nil, fmt.Errorf("+optimize requires %s function as entrypoint or 1+ exported functions", entry)
	}
	// Non-function regions are not removed by upstream. Walk them as roots so
	// their relocation-backed references cannot dangle after optimization.
	for _, chunk := range chunks {
		if !chunk.isFunction() {
			visit(chunk)
		}
	}

	kept := make([]*codeChunk, 0, len(chunks))
	removeNames := make(map[string]struct{})
	removeSymbols := make(map[string]struct{})
	var removed []string
	for _, chunk := range chunks {
		if !chunk.isFunction() || reachable[chunk] {
			kept = append(kept, chunk)
			continue
		}
		for _, symbol := range chunk.symbols {
			if !symbol.IsSectionName() {
				removeSymbols[symbol.Name] = struct{}{}
			}
			if symbol.IsFunction() {
				removeNames[symbol.Name] = struct{}{}
				removed = append(removed, symbol.Name)
			}
		}
	}
	for _, chunk := range kept {
		for target := range analysis.edges[chunk] {
			if !reachable[target] && target.isFunction() {
				return nil, nil, nil, fmt.Errorf("btf: kept code still references optimized function %s", target.displayName())
			}
		}
		for _, relocation := range chunk.relocs {
			if _, removedTarget := removeNames[relocation.SymbolName]; removedTarget {
				return nil, nil, nil, fmt.Errorf("btf: kept code still references optimized function %s", relocation.SymbolName)
			}
		}
	}
	return kept, removed, removeSymbols, nil
}

func shuffleChunks(chunks []*codeChunk, preserveFirst bool, random io.Reader) error {
	functionCount := 0
	for _, chunk := range chunks {
		if chunk.isFunction() {
			functionCount++
		}
	}
	// FunctionDisco is an upstream no-op unless at least two functions exist;
	// inline data labels do not make a one-function program eligible.
	if functionCount <= 1 {
		return nil
	}
	start := 0
	if preserveFirst {
		start = 1
	}
	var buffer [8]byte
	for index := len(chunks) - 1; index > start; index-- {
		if _, err := io.ReadFull(random, buffer[:]); err != nil {
			return fmt.Errorf("btf: shuffle randomness: %w", err)
		}
		value := uint64(buffer[0]) | uint64(buffer[1])<<8 | uint64(buffer[2])<<16 | uint64(buffer[3])<<24 |
			uint64(buffer[4])<<32 | uint64(buffer[5])<<40 | uint64(buffer[6])<<48 | uint64(buffer[7])<<56
		other := start + int(value%uint64(index-start+1))
		chunks[index], chunks[other] = chunks[other], chunks[index]
	}
	if !preserveFirst && !chunks[0].isFunction() {
		firstFunction := -1
		for index, chunk := range chunks {
			if chunk.isFunction() {
				firstFunction = index
				break
			}
		}
		if firstFunction >= 0 {
			chunks = append(chunks[firstFunction:], chunks[:firstFunction]...)
		}
	}
	return nil
}

func rebuildText(object *coff.Object, text *coff.Section, chunks []*codeChunk, analysis *orderAnalysis, removeSymbols map[string]struct{}) error {
	placements := make(map[*codeChunk]uint32, len(chunks))
	auxiliary, err := optimizedFunctionAuxiliary(chunks)
	if err != nil {
		return err
	}
	newData := make([]byte, 0, len(text.Data))
	newRelocations := make([]*coff.Relocation, 0, len(text.Relocations))
	for _, chunk := range chunks {
		newStart := uint32(len(newData))
		retainedEnd := chunk.start + uint32(len(chunk.data))
		placements[chunk] = newStart
		newData = append(newData, chunk.data...)
		for _, symbol := range chunk.symbols {
			if symbol.IsSectionName() {
				continue
			}
			if symbol.Value < chunk.start || symbol.Value >= retainedEnd {
				return fmt.Errorf("btf: symbol %s escaped its code chunk", symbol.Name)
			}
		}
		for _, relocation := range chunk.relocs {
			if relocation.VirtualAddress < chunk.start || relocation.VirtualAddress >= chunk.end {
				return fmt.Errorf("btf: relocation %#x escaped its code chunk", relocation.VirtualAddress)
			}
			if relocation.VirtualAddress >= retainedEnd {
				continue
			}
			if uint64(relocation.VirtualAddress)+4 > uint64(retainedEnd) {
				return fmt.Errorf("btf: relocation %#x straddles optimized padding in %s", relocation.VirtualAddress, chunk.displayName())
			}
			newRelocations = append(newRelocations, relocation)
		}
	}
	if err := repairOrderReferences(newData, placements, analysis); err != nil {
		return err
	}
	// All fallible work is complete. Commit symbol/relocation rebases and the
	// rebuilt section as one transaction.
	for _, chunk := range chunks {
		newStart := placements[chunk]
		for _, symbol := range chunk.symbols {
			if symbol.IsSectionName() {
				continue
			}
			symbol.Value = newStart + (symbol.Value - chunk.start)
		}
		for _, relocation := range chunk.relocs {
			if relocation.VirtualAddress >= chunk.start+uint32(len(chunk.data)) {
				continue
			}
			relocation.VirtualAddress = newStart + (relocation.VirtualAddress - chunk.start)
			relocation.Section = text
		}
	}
	for symbol, records := range auxiliary {
		symbol.AuxiliaryRecords = records
	}
	sort.SliceStable(newRelocations, func(i, j int) bool { return newRelocations[i].VirtualAddress < newRelocations[j].VirtualAddress })
	if len(removeSymbols) != 0 {
		object.RemoveSymbols(removeSymbols)
	}
	text.Data = newData
	text.SizeOfRawData = uint32(len(newData))
	if text.VirtualSize != 0 {
		text.VirtualSize = uint32(len(newData))
	}
	text.Relocations = newRelocations
	return nil
}

func relocationTargetChunk(text *coff.Section, chunks []*codeChunk, relocation *coff.Relocation) *codeChunk {
	if relocation == nil {
		return nil
	}
	if relocation.Symbol != nil && relocation.Symbol.Section == text {
		target := int64(relocation.Symbol.Value)
		if offset, err := relocation.Offset(); err == nil {
			target += int64(offset)
		}
		if target >= 0 && target < int64(len(text.Data)) {
			return chunkAtOffset(chunks, uint32(target))
		}
	}
	return nil
}

func chunkForFunction(chunks []*codeChunk, name string) int {
	for index, chunk := range chunks {
		for _, function := range chunk.functionNames() {
			if function == name {
				return index
			}
		}
	}
	return -1
}

func moveFirst(chunks []*codeChunk, index int) []*codeChunk {
	if index <= 0 {
		return chunks
	}
	result := make([]*codeChunk, 0, len(chunks))
	result = append(result, chunks[index])
	result = append(result, chunks[:index]...)
	result = append(result, chunks[index+1:]...)
	return result
}

func chunkNames(chunks []*codeChunk) []string {
	result := make([]string, len(chunks))
	for index, chunk := range chunks {
		result[index] = chunk.displayName()
	}
	return result
}
