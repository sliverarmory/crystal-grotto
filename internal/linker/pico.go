// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	coffimports "github.com/sliverarmory/crystal-grotto/internal/imports"
)

const (
	// PICOHeaderSize is the byte size of Crystal Palace's PICO_HDR.
	PICOHeaderSize = 16
	// PICOReservedExportMax reserves tags 0 through 7. Tag 7 identifies the
	// optional .cpl_unwind resource.
	PICOReservedExportMax uint32 = 7
	PICOUnwindExportTag   uint32 = 7
)

// Export maps a loader-visible numeric tag to a function in the code region.
// Callers that implement the spec language calculate Tag before calling the
// linker (Crystal Palace uses ROR13 of the user's tag string).
type Export struct {
	Symbol string
	Tag    uint32
}

// PICOOptions controls deterministic PICO generation.
type PICOOptions struct {
	EntrySymbol  string
	RequireEntry bool
	Links        []LinkedSection
	// APIs retains declaration order. As in Crystal Palace, duplicate names are
	// permitted and internal imports resolve to the first matching entry.
	APIs []string
	// Exports retains first-declaration order. Re-declaring a symbol with a
	// different tag replaces its tag, matching the upstream export map while
	// keeping the generated directive stream deterministic.
	Exports []Export

	// MaterializeBSS includes the zero-filled .bss bytes in the payload. The
	// upstream-compatible default omits them and represents them only in the
	// data region's virtual length.
	MaterializeBSS bool
}

// PICOHeader is the fixed 16-byte little-endian prefix consumed by the PICO
// loader. A missing entry point is encoded as EntryAddress == 0xffffffff.
type PICOHeader struct {
	CodeLength     uint32
	DataLength     uint32
	ResourceOffset uint32
	EntryAddress   uint32
}

func (h PICOHeader) MarshalBinary() []byte {
	result := make([]byte, PICOHeaderSize)
	binary.LittleEndian.PutUint32(result[0:4], h.CodeLength)
	binary.LittleEndian.PutUint32(result[4:8], h.DataLength)
	binary.LittleEndian.PutUint32(result[8:12], h.ResourceOffset)
	binary.LittleEndian.PutUint32(result[12:16], h.EntryAddress)
	return result
}

// ParsePICOHeader decodes a header without trusting a following payload.
func ParsePICOHeader(data []byte) (PICOHeader, error) {
	if len(data) < PICOHeaderSize {
		return PICOHeader{}, fmt.Errorf("PICO header is truncated: got %d bytes", len(data))
	}
	return PICOHeader{
		CodeLength:     binary.LittleEndian.Uint32(data[0:4]),
		DataLength:     binary.LittleEndian.Uint32(data[4:8]),
		ResourceOffset: binary.LittleEndian.Uint32(data[8:12]),
		EntryAddress:   binary.LittleEndian.Uint32(data[12:16]),
	}, nil
}

// PICOImage contains both the final wire representation and its deterministic
// components for diagnostics and compatibility tests.
type PICOImage struct {
	Bytes      []byte
	Header     PICOHeader
	Program    []byte
	Code       []byte
	Data       []byte
	CodeLayout *Layout
	DataLayout *Layout
	Directives []Directive

	EntryOffset uint32
	HasEntry    bool
}

type picoRegion uint8

const (
	picoCode picoRegion = iota
	picoData
)

type picoImport struct {
	symbol   string
	module   string
	function string
	slot     *coff.Section
}

type picoTarget struct {
	region    picoRegion
	placement Placement
	symbol    *coff.Symbol
}

type picoPatchup struct {
	source     picoRegion
	target     picoRegion
	patch      uint32
	relocation *coff.Relocation
}

// EmitPICO emits Crystal Palace's deterministic PICO header, loader program,
// code bytes, and data bytes. Randomized BTF transformations are intentionally
// outside this API.
func EmitPICO(object *coff.Object, options PICOOptions) (*PICOImage, error) {
	if object == nil {
		return nil, &Error{Stage: "PICO", Err: errors.New("nil object")}
	}
	if err := validateCOFFModel(object, "PICO validation"); err != nil {
		return nil, err
	}
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return nil, &Error{Stage: "PICO", Err: fmt.Errorf("unsupported machine %s", object.Machine)}
	}
	text := object.GetSection(".text")
	if text == nil {
		return nil, &Error{Stage: "PICO", Err: errors.New("object has no .text section")}
	}

	linkedByName := make(map[string]*coff.Section, len(options.Links))
	var executableLinks, dataLinks []*coff.Section
	for _, linked := range options.Links {
		section, err := linked.section()
		if err != nil {
			return nil, &Error{Stage: "PICO link", Err: err}
		}
		if linkedByName[section.Name] != nil {
			return nil, &Error{Stage: "PICO link", Err: fmt.Errorf("duplicate linked name %q", section.Name)}
		}
		linkedByName[section.Name] = section
		if linked.Executable {
			executableLinks = append(executableLinks, section)
		} else {
			dataLinks = append(dataLinks, section)
		}
	}

	codeEntries := []layoutEntry{{section: text}}
	for _, section := range executableLinks {
		codeEntries = append(codeEntries, layoutEntry{section: section})
	}
	unwind := object.GetSection(".cpl_unwind")
	if unwind != nil {
		codeEntries = append(codeEntries, layoutEntry{section: unwind})
	}
	codeLayout, err := makeLayout(codeEntries)
	if err != nil {
		return nil, &Error{Stage: "PICO code layout", Err: err}
	}

	trackedImports, importsBySymbol, err := discoverPICOImports(object.Machine, codeLayout)
	if err != nil {
		return nil, err
	}
	dataEntries := make([]layoutEntry, 0, len(trackedImports)+len(dataLinks)+3)
	for _, imported := range trackedImports {
		dataEntries = append(dataEntries, layoutEntry{section: imported.slot})
	}
	if section := object.GetSection(".rdata"); section != nil {
		dataEntries = append(dataEntries, layoutEntry{section: section})
	}
	if section := object.GetSection(".data"); section != nil {
		dataEntries = append(dataEntries, layoutEntry{section: section})
	}
	for _, section := range dataLinks {
		dataEntries = append(dataEntries, layoutEntry{section: section})
	}
	if section := object.GetSection(".bss"); section != nil {
		dataEntries = append(dataEntries, layoutEntry{section: section, sparse: !options.MaterializeBSS})
	}
	dataLayout, err := makeLayout(dataEntries)
	if err != nil {
		return nil, &Error{Stage: "PICO data layout", Err: err}
	}

	image := &PICOImage{
		Code:       append([]byte(nil), codeLayout.Bytes...),
		Data:       append([]byte(nil), dataLayout.Bytes...),
		CodeLayout: codeLayout,
		DataLayout: dataLayout,
	}
	entryName := options.EntrySymbol
	if entryName == "" {
		entryName = defaultEntry(object.Machine)
	}
	image.EntryOffset = math.MaxUint32
	if symbol := object.GetSymbol(entryName); symbol != nil && symbol.Section != nil {
		placement, ok := codeLayout.Placement(symbol.Section)
		if !ok {
			return nil, &Error{Stage: "PICO entry", Err: fmt.Errorf("entry symbol %q is not in the code region", entryName)}
		}
		offset, err := checkedAdd32(placement.Offset, symbol.Value)
		if err != nil {
			return nil, &Error{Stage: "PICO entry", Err: fmt.Errorf("entry symbol %q: %w", entryName, err)}
		}
		image.EntryOffset, image.HasEntry = offset, true
	} else if options.RequireEntry {
		return nil, &Error{Stage: "PICO entry", Err: fmt.Errorf("entry symbol %q was not found", entryName)}
	}

	var patchups []picoPatchup
	for _, placement := range codeLayout.Placements {
		for _, relocation := range placement.Section.Relocations {
			patchup, keep, err := applyPICORelocation(object, object.Machine, picoCode, codeLayout, dataLayout, image.Code, linkedByName, importsBySymbol, placement, relocation)
			if err != nil {
				return nil, err
			}
			if keep {
				patchups = append(patchups, patchup)
			}
		}
	}
	for _, placement := range dataLayout.Placements {
		// Import slots and linked byte blobs have no relocations. Sparse .bss
		// relocations are invalid because there is no physical patch site.
		for _, relocation := range placement.Section.Relocations {
			if placement.Sparse {
				return nil, &Error{Stage: "PICO data relocation", Section: placement.Section.Name, Relocation: relocation, Err: errors.New("sparse .bss contains a relocation")}
			}
			patchup, keep, err := applyPICORelocation(object, object.Machine, picoData, codeLayout, dataLayout, image.Data, linkedByName, importsBySymbol, placement, relocation)
			if err != nil {
				return nil, err
			}
			if keep {
				patchups = append(patchups, patchup)
			}
		}
	}

	directives, err := buildPICODirectives(object, options, image, patchups, trackedImports, unwind)
	if err != nil {
		return nil, err
	}
	program, err := EncodeDirectives(directives)
	if err != nil {
		return nil, &Error{Stage: "PICO directives", Err: err}
	}
	resourceOffset := uint64(PICOHeaderSize) + uint64(len(program))
	if resourceOffset > math.MaxUint32 {
		return nil, &Error{Stage: "PICO header", Err: errors.New("loader program makes resource offset exceed 32 bits")}
	}
	image.Directives = cloneDirectives(directives)
	image.Program = program
	image.Header = PICOHeader{
		CodeLength:     codeLayout.VirtualSize,
		DataLength:     dataLayout.VirtualSize,
		ResourceOffset: uint32(resourceOffset),
		EntryAddress:   image.EntryOffset,
	}
	header := image.Header.MarshalBinary()
	total := uint64(len(header)) + uint64(len(program)) + uint64(len(image.Code)) + uint64(len(image.Data))
	if total > uint64(math.MaxInt) {
		return nil, &Error{Stage: "PICO output", Err: errors.New("output allocation overflow")}
	}
	image.Bytes = make([]byte, 0, int(total))
	image.Bytes = append(image.Bytes, header...)
	image.Bytes = append(image.Bytes, program...)
	image.Bytes = append(image.Bytes, image.Code...)
	image.Bytes = append(image.Bytes, image.Data...)
	return image, nil
}

func discoverPICOImports(machine coff.Machine, code *Layout) ([]*picoImport, map[string]*picoImport, error) {
	bySymbol := make(map[string]*picoImport)
	var ordered []*picoImport
	for _, placement := range code.Placements {
		for _, relocation := range placement.Section.Relocations {
			parsed, ok := coffimports.ParseSymbol(relocation.SymbolName)
			// ProgramPICO keys its IAT by the exact relocation symbol. Preserve
			// the first encounter so repeated references share one pointer slot.
			if !ok || bySymbol[relocation.SymbolName] != nil {
				continue
			}
			var pointerSize int
			switch {
			case machine == coff.MachineAMD64 && relocation.Type == coff.RelAMD64Rel32:
				pointerSize = 8
			case machine == coff.MachineI386 && relocation.Type == coff.RelI386Dir32:
				pointerSize = 4
			default:
				return nil, nil, &Error{Stage: "PICO import", Section: placement.Section.Name, Relocation: relocation, Err: fmt.Errorf("import relocation has invalid type %#x for %s", relocation.Type, machine)}
			}
			if parsed.Function == "" {
				return nil, nil, &Error{Stage: "PICO import", Section: placement.Section.Name, Relocation: relocation, Err: errors.New("import function name is empty")}
			}
			slot := coff.NewSection(relocation.SymbolName, make([]byte, pointerSize))
			imported := &picoImport{symbol: relocation.SymbolName, module: parsed.Module, function: parsed.Function, slot: slot}
			bySymbol[imported.symbol] = imported
			ordered = append(ordered, imported)
		}
	}
	return ordered, bySymbol, nil
}

func applyPICORelocation(object *coff.Object, machine coff.Machine, sourceRegion picoRegion, code, data *Layout, output []byte, linkedByName map[string]*coff.Section, importsBySymbol map[string]*picoImport, source Placement, relocation *coff.Relocation) (picoPatchup, bool, error) {
	stage := "PICO code relocation"
	if sourceRegion == picoData {
		stage = "PICO data relocation"
	}
	patchOffset, err := checkedAdd32(source.Offset, relocation.VirtualAddress)
	if err != nil {
		return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: err}
	}
	if uint64(patchOffset)+4 > uint64(len(output)) {
		return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: errors.New("patch site is outside physical region")}
	}
	target, err := resolvePICOTarget(object, code, data, linkedByName, importsBySymbol, relocation)
	if err != nil {
		return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: err}
	}
	addend, err := relocation.Offset()
	if err != nil {
		return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: err}
	}
	targetOffset := int64(target.placement.Offset) + int64(addend)
	if target.symbol != nil {
		targetOffset += int64(target.symbol.Value)
	}
	patchup := picoPatchup{source: sourceRegion, target: target.region, patch: patchOffset, relocation: relocation}

	if sourceRegion == picoCode {
		switch {
		case machine == coff.MachineAMD64 && relocation.Type >= coff.RelAMD64Rel32 && relocation.Type <= coff.RelAMD64Rel32_5:
			delta := targetOffset - (int64(patchOffset) + int64(relocation.FromOffset()))
			if err := writeInt32(output, patchOffset, delta); err != nil {
				return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: err}
			}
			return patchup, target.region != picoCode, nil
		case machine == coff.MachineAMD64 && relocation.Type == coff.RelAMD64Addr32NB:
			// Crystal Palace deliberately leaves a .text section-relative
			// ADDR32NB untouched (notably for unwind metadata).
			if relocation.SymbolName == ".text" {
				return picoPatchup{}, false, nil
			}
			if err := writeAbsolute32(output, patchOffset, targetOffset); err != nil {
				return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: err}
			}
			return picoPatchup{}, false, nil
		case machine == coff.MachineI386 && relocation.Type == coff.RelI386Dir32:
			if err := writeAbsolute32(output, patchOffset, targetOffset); err != nil {
				return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: err}
			}
			return patchup, true, nil
		case machine == coff.MachineI386 && relocation.Type == coff.RelI386Rel32:
			delta := targetOffset - (int64(patchOffset) + 4)
			if err := writeInt32(output, patchOffset, delta); err != nil {
				return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: err}
			}
			return patchup, target.region != picoCode, nil
		default:
			return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: fmt.Errorf("cannot offline-process relocation type %#x for %s", relocation.Type, machine)}
		}
	}

	if (relocation.Symbol != nil && relocation.Symbol.Name == ".text") || relocation.SymbolName == ".text" {
		return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: errors.New("suspected jump table; compile with -fno-jump-tables or equivalent")}
	}
	switch {
	case machine == coff.MachineAMD64 && relocation.Type >= coff.RelAMD64Rel32 && relocation.Type <= coff.RelAMD64Rel32_5:
		return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: errors.New("relative relocation in data is unsupported")}
	case machine == coff.MachineAMD64 && relocation.Type == coff.RelAMD64Addr64:
		if uint64(patchOffset)+8 > uint64(len(output)) {
			return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: errors.New("ADDR64 patch site is outside physical region")}
		}
		if err := writeAbsolute32(output, patchOffset, targetOffset); err != nil {
			return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: err}
		}
		return patchup, true, nil
	case machine == coff.MachineI386 && relocation.Type == coff.RelI386Dir32:
		if err := writeAbsolute32(output, patchOffset, targetOffset); err != nil {
			return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: err}
		}
		return patchup, true, nil
	default:
		return picoPatchup{}, false, &Error{Stage: stage, Section: source.Section.Name, Relocation: relocation, Err: fmt.Errorf("cannot offline-process relocation type %#x for %s", relocation.Type, machine)}
	}
}

func resolvePICOTarget(object *coff.Object, code, data *Layout, linkedByName map[string]*coff.Section, importsBySymbol map[string]*picoImport, relocation *coff.Relocation) (picoTarget, error) {
	if relocation.Symbol != nil && relocation.Symbol.Section != nil {
		if placement, ok := code.Placement(relocation.Symbol.Section); ok {
			return picoTarget{region: picoCode, placement: placement, symbol: relocation.Symbol}, nil
		}
		if placement, ok := data.Placement(relocation.Symbol.Section); ok {
			return picoTarget{region: picoData, placement: placement, symbol: relocation.Symbol}, nil
		}
	}
	if object != nil {
		if symbol := object.GetSymbol(relocation.SymbolName); symbol != nil && symbol.Section != nil {
			if placement, ok := code.Placement(symbol.Section); ok {
				return picoTarget{region: picoCode, placement: placement, symbol: symbol}, nil
			}
			if placement, ok := data.Placement(symbol.Section); ok {
				return picoTarget{region: picoData, placement: placement, symbol: symbol}, nil
			}
		}
	}
	if linked := linkedByName[relocation.SymbolName]; linked != nil {
		if placement, ok := code.Placement(linked); ok {
			return picoTarget{region: picoCode, placement: placement}, nil
		}
		if placement, ok := data.Placement(linked); ok {
			return picoTarget{region: picoData, placement: placement}, nil
		}
	}
	if imported := importsBySymbol[relocation.SymbolName]; imported != nil {
		if placement, ok := data.Placement(imported.slot); ok {
			return picoTarget{region: picoData, placement: placement}, nil
		}
	}
	return picoTarget{}, fmt.Errorf("unresolved or omitted symbol %q", relocation.SymbolName)
}

func buildPICODirectives(object *coff.Object, options PICOOptions, image *PICOImage, patchups []picoPatchup, trackedImports []*picoImport, unwind *coff.Section) ([]Directive, error) {
	directives := []Directive{
		directiveUint32(PICOInstructionCopy, PICOContextCode, 0, 0, uint32(len(image.Code))),
		directiveUint32(PICOInstructionCopy, PICOContextData, uint32(len(image.Code)), 0, uint32(len(image.Data))),
	}
	for _, patchup := range patchups {
		relocation := patchup.relocation
		if object.Machine == coff.MachineAMD64 && relocation.Type >= coff.RelAMD64Rel32 && relocation.Type <= coff.RelAMD64Rel32_5 || object.Machine == coff.MachineI386 && relocation.Type == coff.RelI386Rel32 {
			if patchup.source != picoCode || patchup.target != picoData {
				return nil, &Error{Stage: "PICO directive", Section: relocation.Section.Name, Relocation: relocation, Err: errors.New("PATCH_DIFF only supports code-to-data relocations")}
			}
			directives = append(directives, directiveUint32(PICOInstructionPatchDiff, 0, patchup.patch))
			continue
		}
		if object.Machine == coff.MachineAMD64 && relocation.Type != coff.RelAMD64Addr64 || object.Machine == coff.MachineI386 && relocation.Type != coff.RelI386Dir32 {
			return nil, &Error{Stage: "PICO directive", Section: relocation.Section.Name, Relocation: relocation, Err: errors.New("unsupported runtime patch relocation")}
		}
		option := uint8(PICOPatchTextText)
		switch {
		case patchup.source == picoCode && patchup.target == picoData:
			option = PICOPatchTextData
		case patchup.source == picoData && patchup.target == picoCode:
			option = PICOPatchDataText
		case patchup.source == picoData && patchup.target == picoData:
			option = PICOPatchDataData
		}
		directives = append(directives, directiveUint32(PICOInstructionPatch, option, patchup.patch))
	}

	// Upstream uses HashMap for modules, functions, local APIs, and exports, so
	// its directive byte order is deliberately unspecified. Relocation encounter
	// order gives the Go port deterministic bytes while emitting the same
	// semantic loader operations.
	seenModules := make(map[string]bool)
	for _, imported := range trackedImports {
		if imported.module == "" || seenModules[imported.module] {
			continue
		}
		seenModules[imported.module] = true
		load, err := directiveString(PICOInstructionLoadLibrary, imported.module)
		if err != nil {
			return nil, &Error{Stage: "PICO import directive", Err: fmt.Errorf("module %q: %w", imported.module, err)}
		}
		directives = append(directives, load)
		for _, function := range trackedImports {
			if function.module != imported.module {
				continue
			}
			get, err := directiveString(PICOInstructionGetProcAddress, function.function)
			if err != nil {
				return nil, &Error{Stage: "PICO import directive", Err: fmt.Errorf("function %q: %w", function.function, err)}
			}
			placement, ok := image.DataLayout.Placement(function.slot)
			if !ok {
				return nil, &Error{Stage: "PICO import directive", Err: fmt.Errorf("slot for %q was not laid out", function.symbol)}
			}
			directives = append(directives, get, directiveUint32(PICOInstructionPatchFunction, 0, placement.Offset))
		}
	}

	apis := options.APIs
	if len(apis) == 0 {
		apis = []string{"LoadLibraryA", "GetProcAddress"}
	}
	if len(apis) < 2 || apis[0] != "LoadLibraryA" || apis[1] != "GetProcAddress" {
		return nil, &Error{Stage: "PICO APIs", Err: errors.New("LoadLibraryA and GetProcAddress are required as the first two API entries")}
	}
	apiIndex := make(map[string]int, len(apis))
	for index, api := range apis {
		if api == "" {
			return nil, &Error{Stage: "PICO APIs", Err: fmt.Errorf("API entry %d is empty", index)}
		}
		// ExportObject.getAPI() linearly scans the upstream list, so repeated
		// entries deliberately retain the first index.
		if _, exists := apiIndex[api]; !exists {
			apiIndex[api] = index
		}
	}
	for _, imported := range trackedImports {
		if imported.module != "" {
			continue
		}
		index, ok := apiIndex[imported.function]
		if !ok {
			return nil, &Error{Stage: "PICO APIs", Err: fmt.Errorf("function %s is not imported and not in MODULE$Function format", imported.function)}
		}
		if index >= math.MaxUint8 {
			return nil, &Error{Stage: "PICO APIs", Err: fmt.Errorf("API %q at index %d exceeds encodable PATCH_FUNC options", imported.function, index)}
		}
		placement, ok := image.DataLayout.Placement(imported.slot)
		if !ok {
			return nil, &Error{Stage: "PICO APIs", Err: fmt.Errorf("slot for %q was not laid out", imported.symbol)}
		}
		directives = append(directives, directiveUint32(PICOInstructionPatchFunction, uint8(index+1), placement.Offset))
	}

	exports, err := normalizePICOExports(options.Exports)
	if err != nil {
		return nil, err
	}
	for _, exported := range exports {
		symbol := object.GetSymbol(exported.Symbol)
		if symbol == nil || symbol.Section == nil {
			return nil, &Error{Stage: "PICO export", Err: fmt.Errorf("symbol %q does not exist", exported.Symbol)}
		}
		if !symbol.IsFunction() {
			return nil, &Error{Stage: "PICO export", Err: fmt.Errorf("symbol %q is not a function", exported.Symbol)}
		}
		placement, ok := image.CodeLayout.Placement(symbol.Section)
		if !ok {
			return nil, &Error{Stage: "PICO export", Err: fmt.Errorf("function %q is not in the code region", exported.Symbol)}
		}
		offset, err := checkedAdd32(placement.Offset, symbol.Value)
		if err != nil {
			return nil, &Error{Stage: "PICO export", Err: fmt.Errorf("function %q: %w", exported.Symbol, err)}
		}
		directives = append(directives, directiveUint32(PICOInstructionExport, 0, exported.Tag, offset))
	}
	if unwind != nil {
		placement, ok := image.CodeLayout.Placement(unwind)
		if !ok {
			return nil, &Error{Stage: "PICO unwind export", Err: errors.New(".cpl_unwind was not laid out")}
		}
		directives = append(directives, directiveUint32(PICOInstructionExport, 0, PICOUnwindExportTag, placement.Offset))
	}
	directives = append(directives, Directive{Type: PICOInstructionComplete})
	return directives, nil
}

// normalizePICOExports models sequential calls to Exports.export. Crystal
// Palace stores exports in a HashMap: a new tag replaces a prior tag for the
// same function, while a tag already present in the current map is rejected.
// Keeping the first slice position gives the Go port stable output without
// assigning meaning to Java HashMap iteration order.
func normalizePICOExports(exports []Export) ([]Export, error) {
	result := make([]Export, 0, len(exports))
	bySymbol := make(map[string]int, len(exports))
	byTag := make(map[uint32]string, len(exports))
	for _, exported := range exports {
		if exported.Symbol == "" {
			return nil, &Error{Stage: "PICO export", Err: errors.New("export symbol is empty")}
		}
		if exported.Tag <= PICOReservedExportMax {
			return nil, &Error{Stage: "PICO export", Err: fmt.Errorf("tag %#x for %q is reserved", exported.Tag, exported.Symbol)}
		}
		if previous, exists := byTag[exported.Tag]; exists {
			return nil, &Error{Stage: "PICO export", Err: fmt.Errorf("tag %#x for %q conflicts with %q", exported.Tag, exported.Symbol, previous)}
		}
		if index, exists := bySymbol[exported.Symbol]; exists {
			delete(byTag, result[index].Tag)
			result[index] = exported
		} else {
			bySymbol[exported.Symbol] = len(result)
			result = append(result, exported)
		}
		byTag[exported.Tag] = exported.Symbol
	}
	return result, nil
}

func cloneDirectives(directives []Directive) []Directive {
	result := make([]Directive, len(directives))
	for index, directive := range directives {
		result[index] = Directive{Type: directive.Type, Option: directive.Option, Data: append([]byte(nil), directive.Data...)}
	}
	return result
}
