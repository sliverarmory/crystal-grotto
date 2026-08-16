// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package hookresolve

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
)

var applyMu sync.Mutex

type stubRelocation struct {
	offset  uint32
	wrapper string
	typeID  uint16
}

type plannedSite struct {
	relocationIndex int
	relocation      *coff.Relocation
	context         string
	stubName        string
	stubOffset      uint32
	stub            []byte
	stubRelocations []stubRelocation
	entries         int
}

// Apply transactionally expands every canonical __resolve_hook CALL into a
// call to a generated resolver stub. The returned object is independent of
// object and has passed a COFF marshal/parse validation round trip.
func Apply(ctx context.Context, object *coff.Object, model *hooks.Model, options Options) (*coff.Object, Report, error) {
	if ctx == nil {
		return nil, Report{}, fmt.Errorf("%w: nil context", ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return nil, Report{}, fmt.Errorf("hookresolve: %w", err)
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
	random, err := randomSource(options)
	if err != nil {
		return nil, Report{}, err
	}

	// The COFF model is a mutable pointer graph. Serialize clone/apply/validate
	// under one package lock so concurrent callers may safely share an input.
	applyMu.Lock()
	defer applyMu.Unlock()
	candidate, err := cloneObject(object)
	if err != nil {
		return nil, Report{}, fmt.Errorf("%w: clone input: %v", ErrInvalidModel, err)
	}
	text := candidate.GetSection(".text")
	if text == nil {
		return nil, Report{}, fmt.Errorf("%w: object has no .text section", ErrInvalidModel)
	}

	symbol := "__resolve_hook"
	relocationType := uint16(coff.RelAMD64Rel32)
	if candidate.Machine == coff.MachineI386 {
		symbol = "___resolve_hook"
		relocationType = coff.RelI386Rel32
	}
	type relocationSite struct {
		index      int
		relocation *coff.Relocation
	}
	var matching []relocationSite
	for index, relocation := range text.Relocations {
		if relocation == nil {
			return nil, Report{}, fmt.Errorf("%w: .text relocation %d is nil", ErrInvalidModel, index)
		}
		if relocation.SymbolName == symbol {
			matching = append(matching, relocationSite{index: index, relocation: relocation})
		}
	}
	if len(matching) == 0 {
		return candidate, Report{}, nil
	}
	sort.SliceStable(matching, func(i, j int) bool {
		if matching[i].relocation.VirtualAddress != matching[j].relocation.VirtualAddress {
			return matching[i].relocation.VirtualAddress < matching[j].relocation.VirtualAddress
		}
		return matching[i].index < matching[j].index
	})

	reservedSymbols := make(map[string]struct{}, len(candidate.Symbols)+len(matching))
	for _, existing := range candidate.Symbols {
		if existing != nil {
			reservedSymbols[existing.Name] = struct{}{}
		}
	}
	baseEntries := model.ResolveHooks()
	report := Report{}
	planned := make([]*plannedSite, 0, len(matching))
	seenInstruction := make(map[uint32]bool, len(matching))
	for siteIndex, match := range matching {
		if err := ctx.Err(); err != nil {
			return nil, Report{}, fmt.Errorf("hookresolve: planning: %w", err)
		}
		relocation := match.relocation
		fail := func(err error) error {
			return &SiteError{Section: text.Name, Offset: relocation.VirtualAddress, Symbol: relocation.SymbolName, Err: err}
		}
		if relocation.Type != relocationType {
			return nil, Report{}, fail(fmt.Errorf("%w: relocation type %#x, want %#x", ErrUnsupportedForm, relocation.Type, relocationType))
		}
		if relocation.VirtualAddress == 0 || uint64(relocation.VirtualAddress)+4 > uint64(len(text.Data)) || text.Data[relocation.VirtualAddress-1] != 0xe8 {
			return nil, Report{}, fail(fmt.Errorf("%w: intrinsic requires CALL rel32", ErrUnsupportedForm))
		}
		instruction := relocation.VirtualAddress - 1
		if seenInstruction[instruction] {
			return nil, Report{}, fail(fmt.Errorf("%w: duplicate intrinsic relocation", ErrInvalidModel))
		}
		seenInstruction[instruction] = true
		function := relocation.ContainingFunction()
		if function == nil || !function.IsFunction() {
			return nil, Report{}, fail(fmt.Errorf("%w: intrinsic is not inside a named function", ErrInvalidModel))
		}

		entries := append([]hooks.ResolveHook(nil), baseEntries...)
		draws, err := shuffle(entries, random)
		report.RandomDraws += draws
		if err != nil {
			return nil, Report{}, fail(err)
		}
		resolved := make([]hooks.ResolveHook, 0, len(entries))
		wrappers := make([]string, 0, len(entries))
		for _, entry := range entries {
			wrapper, ok := model.ResolveRegisteredHook(function.Name, entry)
			if !ok {
				continue
			}
			wrapperSymbol := candidate.GetSymbol(wrapper)
			if wrapperSymbol == nil || wrapperSymbol.Section == nil {
				// Crystal Palace skips entries whose selected wrapper symbol is
				// absent in this linked object.
				continue
			}
			resolved = append(resolved, entry)
			wrappers = append(wrappers, wrapper)
		}
		stub, relocations, err := encodeStub(candidate.Machine, resolved, wrappers)
		if err != nil {
			return nil, Report{}, fail(err)
		}
		name := reserveSymbol(reservedSymbols, fmt.Sprintf("__cpl_hookresolve_%08x", siteIndex))
		planned = append(planned, &plannedSite{
			relocationIndex: match.index, relocation: relocation, context: function.Name,
			stubName: name, stub: stub, stubRelocations: relocations, entries: len(resolved),
		})
	}

	stubSection := coff.NewSection(reserveSection(candidate), nil)
	stubSection.Characteristics = coff.SectionCode | coff.SectionMemExecute | coff.SectionMemRead
	stubSection.Alignment = 16
	stubSection.Data = []byte{0xe9, 0, 0, 0, 0}
	for _, site := range planned {
		if uint64(len(stubSection.Data))+uint64(len(site.stub)) > math.MaxUint32 || uint64(len(stubSection.Data))+uint64(len(site.stub)) > uint64(math.MaxInt) {
			return nil, Report{}, fmt.Errorf("%w: generated stub section is too large", ErrInvalidModel)
		}
		site.stubOffset = uint32(len(stubSection.Data))
		stubSection.Data = append(stubSection.Data, site.stub...)
	}
	stubLength := len(stubSection.Data) - 5
	if stubLength > math.MaxInt32 {
		return nil, Report{}, fmt.Errorf("%w: fallthrough guard exceeds REL32 range", ErrInvalidModel)
	}
	binary.LittleEndian.PutUint32(stubSection.Data[1:5], uint32(stubLength))
	stubSection.SizeOfRawData = uint32(len(stubSection.Data))
	if err := candidate.AddSection(stubSection); err != nil {
		return nil, Report{}, fmt.Errorf("%w: add stub section: %v", ErrInvalidModel, err)
	}
	for _, site := range planned {
		stubSymbol := &coff.Symbol{
			Name: site.stubName, Value: site.stubOffset, Section: stubSection,
			Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassStatic,
		}
		if err := candidate.AddSymbol(stubSymbol); err != nil {
			return nil, Report{}, fmt.Errorf("%w: add stub symbol %q: %v", ErrInvalidModel, site.stubName, err)
		}
		binary.LittleEndian.PutUint32(text.Data[site.relocation.VirtualAddress:site.relocation.VirtualAddress+4], 0)
		site.relocation.SymbolName = stubSymbol.Name
		site.relocation.Symbol = stubSymbol
		site.relocation.Type = relocationType
		for _, generated := range site.stubRelocations {
			wrapper := candidate.GetSymbol(generated.wrapper)
			if wrapper == nil || wrapper.Section == nil {
				return nil, Report{}, fmt.Errorf("%w: wrapper %q disappeared", ErrInvalidModel, generated.wrapper)
			}
			address := uint64(site.stubOffset) + uint64(generated.offset)
			if address > math.MaxUint32 {
				return nil, Report{}, fmt.Errorf("%w: generated relocation address overflows", ErrInvalidModel)
			}
			stubSection.Relocations = append(stubSection.Relocations, &coff.Relocation{
				Section: stubSection, VirtualAddress: uint32(address), SymbolName: wrapper.Name,
				Symbol: wrapper, Type: generated.typeID,
			})
		}
		report.RewrittenSites++
		report.ResolverEntries += site.entries
	}
	report.StubSection = stubSection.Name
	validated, err := cloneObject(candidate)
	if err != nil {
		return nil, Report{}, fmt.Errorf("%w: validate output: %v", ErrInvalidModel, err)
	}
	return validated, report, nil
}

func cloneObject(object *coff.Object) (*coff.Object, error) {
	encoded, err := coffwrite.Marshal(object)
	if err != nil {
		return nil, err
	}
	return coff.Parse(encoded)
}

func reserveSection(object *coff.Object) string {
	base := ".text$cpl_hookresolve"
	if object.GetSection(base) == nil {
		return base
	}
	for index := 1; ; index++ {
		name := fmt.Sprintf("%s$%d", base, index)
		if object.GetSection(name) == nil {
			return name
		}
	}
}

func reserveSymbol(reserved map[string]struct{}, base string) string {
	name := base
	for suffix := 1; ; suffix++ {
		if _, exists := reserved[name]; !exists {
			reserved[name] = struct{}{}
			return name
		}
		name = fmt.Sprintf("%s_%d", base, suffix)
	}
}

func encodeStub(machine coff.Machine, entries []hooks.ResolveHook, wrappers []string) ([]byte, []stubRelocation, error) {
	if len(entries) != len(wrappers) {
		return nil, nil, fmt.Errorf("%w: entry/wrapper length mismatch", ErrInvalidModel)
	}
	if machine == coff.MachineAMD64 {
		return encodeX64(entries, wrappers)
	}
	if machine == coff.MachineI386 {
		return encodeX86(entries, wrappers)
	}
	return nil, nil, fmt.Errorf("%w: unsupported machine %s", ErrInvalidInput, machine)
}

func encodeX64(entries []hooks.ResolveHook, wrappers []string) ([]byte, []stubRelocation, error) {
	var code []byte
	var relocations []stubRelocation
	var doneBranches []int
	for index, entry := range entries {
		code = append(code, 0xba)
		code = binary.LittleEndian.AppendUint32(code, entry.FunctionHash())
		code = append(code, 0x39, 0xd1, 0x0f, 0x85, 0, 0, 0, 0)
		jneField := len(code) - 4
		code = append(code, 0x48, 0x8d, 0x05, 0, 0, 0, 0)
		relocations = append(relocations, stubRelocation{offset: uint32(len(code) - 4), wrapper: wrappers[index], typeID: coff.RelAMD64Rel32})
		code = append(code, 0xe9, 0, 0, 0, 0)
		doneBranches = append(doneBranches, len(code)-4)
		if err := patchRelative(code, jneField, len(code)); err != nil {
			return nil, nil, err
		}
	}
	code = append(code, 0x48, 0x31, 0xc0)
	done := len(code)
	code = append(code, 0xc3)
	for _, field := range doneBranches {
		if err := patchRelative(code, field, done); err != nil {
			return nil, nil, err
		}
	}
	return code, relocations, nil
}

func encodeX86(entries []hooks.ResolveHook, wrappers []string) ([]byte, []stubRelocation, error) {
	code := []byte{0x8b, 0x4c, 0x24, 0x04}
	var relocations []stubRelocation
	var doneBranches []int
	for index, entry := range entries {
		code = append(code, 0xba)
		code = binary.LittleEndian.AppendUint32(code, entry.FunctionHash())
		code = append(code, 0x39, 0xd1, 0x0f, 0x85, 0, 0, 0, 0)
		jneField := len(code) - 4
		code = append(code, 0xb8, 0, 0, 0, 0)
		relocations = append(relocations, stubRelocation{offset: uint32(len(code) - 4), wrapper: wrappers[index], typeID: coff.RelI386Dir32})
		code = append(code, 0xe9, 0, 0, 0, 0)
		doneBranches = append(doneBranches, len(code)-4)
		if err := patchRelative(code, jneField, len(code)); err != nil {
			return nil, nil, err
		}
	}
	code = append(code, 0x31, 0xc0)
	done := len(code)
	code = append(code, 0xc3)
	for _, field := range doneBranches {
		if err := patchRelative(code, field, done); err != nil {
			return nil, nil, err
		}
	}
	return code, relocations, nil
}

func patchRelative(code []byte, field, target int) error {
	if field < 0 || field+4 > len(code) || target < 0 || target > len(code) {
		return fmt.Errorf("%w: invalid generated branch", ErrInvalidModel)
	}
	delta := int64(target) - int64(field+4)
	if delta < math.MinInt32 || delta > math.MaxInt32 {
		return fmt.Errorf("%w: generated branch exceeds REL32 range", ErrInvalidModel)
	}
	binary.LittleEndian.PutUint32(code[field:field+4], uint32(int32(delta)))
	return nil
}
