// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package resolver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

// ErrInvalidRewritePlan identifies a plan/object mismatch or a backend
// invariant violation. It is distinct from ErrUnsupportedForm, which is
// returned while classifying source instructions.
var ErrInvalidRewritePlan = errors.New("resolver: invalid rewrite plan")

// BackendError identifies the site rejected by BuiltinBackend.
type BackendError struct {
	Site int
	Form Form
	Err  error
}

func (e *BackendError) Error() string {
	return fmt.Sprintf("resolver: builtin backend site %d (%s): %v", e.Site, e.Form, e.Err)
}

func (e *BackendError) Unwrap() error { return e.Err }

// BuiltinBackend replaces each import instruction in place with a same-length
// direct branch to a resolver trampoline in a guarded code subsection. Because
// no original byte changes position, existing symbols, local branch
// displacements, fallthrough order, and unrelated relocation addresses remain
// valid. The output is semantically compatible with ResolveAPI's supported
// forms; it is deliberately not Iced's byte-for-byte inline encoding.
// BuiltinBackend does not synthesize Windows unwind metadata for its generated
// subsection, so callers that require asynchronous exception unwinding through
// resolver instrumentation must use a backend that also rebuilds pdata/xdata.
type BuiltinBackend struct{}

var _ RewriteBackend = BuiltinBackend{}

// ApplyBuiltin applies the built-in deterministic encoder transactionally.
func ApplyBuiltin(object *coff.Object, configuration Configuration) (*coff.Object, RewritePlan, error) {
	return Apply(object, configuration, BuiltinBackend{})
}

type encodedSite struct {
	planIndex        int
	site             Site
	section          *coff.Section
	start            uint32
	length           uint32
	branchOpcode     byte
	stub             []byte
	helperCallOffset uint32
	stubOffset       uint32
	stubSymbol       *coff.Symbol
}

// RewriteResolvers implements RewriteBackend. Callers normally use
// ApplyBuiltin so this mutation occurs only on Apply's private COFF clone.
func (BuiltinBackend) RewriteResolvers(object *coff.Object, plan RewritePlan) error {
	encoded, err := prepareEncodedSites(object, plan)
	if err != nil {
		return err
	}
	if len(encoded) == 0 {
		return nil
	}

	if len(object.Sections) >= math.MaxInt16 {
		return fmt.Errorf("%w: cannot add resolver stub section to %d-section object", ErrInvalidRewritePlan, len(object.Sections))
	}
	bySection := make(map[*coff.Section][]*encodedSite)
	for _, site := range encoded {
		bySection[site.section] = append(bySection[site.section], site)
	}
	for _, sites := range bySection {
		sort.Slice(sites, func(i, j int) bool { return sites[i].planIndex < sites[j].planIndex })
	}

	// Keep generated code in its own guarded .text subsection. Existing code
	// and function extents therefore do not grow, and accidental fallthrough
	// from a preceding subsection jumps over every resolver stub.
	stubSection := coff.NewSection(reserveStubSectionName(object), nil)
	stubSection.Characteristics = coff.SectionCode | coff.SectionMemExecute | coff.SectionMemRead
	stubSection.Alignment = 16
	stubData := []byte{0xe9, 0, 0, 0, 0}
	for _, site := range encoded {
		site.stubOffset = uint32(len(stubData))
		if uint64(len(stubData))+uint64(len(site.stub)) > math.MaxUint32 || uint64(len(stubData))+uint64(len(site.stub)) > uint64(math.MaxInt) {
			return &BackendError{Site: site.planIndex, Form: site.site.Form, Err: fmt.Errorf("%w: resolver stub section exceeds supported size", ErrInvalidRewritePlan)}
		}
		stubData = append(stubData, site.stub...)
		site.stubSymbol = &coff.Symbol{
			Name: site.site.StubSymbol, Value: site.stubOffset, Section: stubSection,
			Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassStatic,
		}
	}
	stubLength := len(stubData) - 5
	if stubLength > math.MaxInt32 {
		return fmt.Errorf("%w: resolver stub fallthrough guard exceeds REL32 range", ErrInvalidRewritePlan)
	}
	binary.LittleEndian.PutUint32(stubData[1:5], uint32(stubLength))
	stubSection.Data = stubData
	stubSection.SizeOfRawData = uint32(len(stubData))

	// All names and sizes were validated before this point. AddSection installs
	// the conventional section symbol; the remaining symbol additions cannot
	// fail for a structurally consistent object.
	if err := object.AddSection(stubSection); err != nil {
		return fmt.Errorf("%w: add resolver stub section: %v", ErrInvalidRewritePlan, err)
	}
	for _, site := range encoded {
		if err := object.AddSymbol(site.stubSymbol); err != nil {
			return &BackendError{Site: site.planIndex, Form: site.site.Form, Err: fmt.Errorf("%w: add stub symbol: %v", ErrInvalidRewritePlan, err)}
		}
	}

	for section, sites := range bySection {
		data := append([]byte(nil), section.Data...)
		replacements := make(map[int]*encodedSite, len(sites))
		for _, site := range sites {
			replacements[site.site.RelocationIndex] = site
			for offset := site.start; offset < site.start+site.length-5; offset++ {
				data[offset] = 0x90
			}
			branch := site.start + site.length - 5
			data[branch] = site.branchOpcode
			for offset := branch + 1; offset < branch+5; offset++ {
				data[offset] = 0
			}
		}
		relocations := make([]*coff.Relocation, 0, len(section.Relocations))
		for index, relocation := range section.Relocations {
			if replacement := replacements[index]; replacement != nil {
				relocationType := coff.RelI386Rel32
				if object.Machine == coff.MachineAMD64 {
					relocationType = coff.RelAMD64Rel32
				}
				relocations = append(relocations, &coff.Relocation{
					Section: section, VirtualAddress: replacement.site.Offset,
					SymbolName: replacement.stubSymbol.Name, Symbol: replacement.stubSymbol, Type: relocationType,
				})
				continue
			}
			relocations = append(relocations, relocation)
		}
		section.Data = data
		section.Relocations = relocations
	}

	for _, site := range encoded {
		helper := object.GetSymbol(site.site.Resolver.Function)
		relocationType := coff.RelI386Rel32
		if object.Machine == coff.MachineAMD64 {
			relocationType = coff.RelAMD64Rel32
		}
		stubSection.Relocations = append(stubSection.Relocations, &coff.Relocation{
			Section: stubSection, VirtualAddress: site.stubOffset + site.helperCallOffset,
			SymbolName: helper.Name, Symbol: helper, Type: relocationType,
		})
	}
	return nil
}

func prepareEncodedSites(object *coff.Object, plan RewritePlan) ([]*encodedSite, error) {
	if object == nil {
		return nil, fmt.Errorf("%w: nil COFF object", ErrInvalidRewritePlan)
	}
	if object.Machine != plan.Machine {
		return nil, fmt.Errorf("%w: plan machine %s differs from object machine %s", ErrInvalidRewritePlan, plan.Machine, object.Machine)
	}
	result := make([]*encodedSite, 0, len(plan.Sites))
	overlaps := make(map[*coff.Section][][2]uint32)
	stubNames := make(map[string]struct{}, len(plan.Sites))
	for index, site := range plan.Sites {
		fail := func(err error) ([]*encodedSite, error) {
			return nil, &BackendError{Site: index, Form: site.Form, Err: err}
		}
		if site.SectionIndex < 0 || site.SectionIndex >= len(object.Sections) {
			return fail(fmt.Errorf("%w: section index %d is out of range", ErrInvalidRewritePlan, site.SectionIndex))
		}
		section := object.Sections[site.SectionIndex]
		if section == nil || section.Name != site.SectionName {
			return fail(fmt.Errorf("%w: section identity changed", ErrInvalidRewritePlan))
		}
		if site.RelocationIndex < 0 || site.RelocationIndex >= len(section.Relocations) {
			return fail(fmt.Errorf("%w: relocation index %d is out of range", ErrInvalidRewritePlan, site.RelocationIndex))
		}
		relocation := section.Relocations[site.RelocationIndex]
		if relocation == nil || relocation.Section != section || relocation.VirtualAddress != site.Offset || relocation.SymbolName != site.Symbol {
			return fail(fmt.Errorf("%w: relocation identity changed", ErrInvalidRewritePlan))
		}
		form, destination, err := classify(object.Machine, section.Data, relocation)
		if err != nil {
			return fail(fmt.Errorf("%w: source instruction changed: %v", ErrInvalidRewritePlan, err))
		}
		if form != site.Form || destination != site.Destination {
			return fail(fmt.Errorf("%w: source instruction is %s to %s, plan records %s to %s", ErrInvalidRewritePlan, form, destination, site.Form, site.Destination))
		}
		start, length, branch, err := replacementShape(site)
		if err != nil {
			return fail(err)
		}
		if uint64(start)+uint64(length) > uint64(len(section.Data)) {
			return fail(fmt.Errorf("%w: source instruction exceeds section bounds", ErrInvalidRewritePlan))
		}
		for _, span := range overlaps[section] {
			if start < span[1] && span[0] < start+length {
				return fail(fmt.Errorf("%w: source instruction overlaps another resolver site", ErrInvalidRewritePlan))
			}
		}
		overlaps[section] = append(overlaps[section], [2]uint32{start, start + length})
		if site.StubSymbol == "" {
			return fail(fmt.Errorf("%w: empty stub symbol", ErrInvalidRewritePlan))
		}
		if _, duplicate := stubNames[site.StubSymbol]; duplicate || object.GetSymbol(site.StubSymbol) != nil {
			return fail(fmt.Errorf("%w: stub symbol %q is not available", ErrInvalidRewritePlan, site.StubSymbol))
		}
		stubNames[site.StubSymbol] = struct{}{}
		if err := validateResolverFunction(object, site.Resolver.Function); err != nil {
			return fail(fmt.Errorf("%w: %v", ErrInvalidRewritePlan, err))
		}
		stub, helperCallOffset, err := encodeStub(object.Machine, site)
		if err != nil {
			return fail(err)
		}
		result = append(result, &encodedSite{
			planIndex: index, site: site, section: section,
			start: start, length: length, branchOpcode: branch,
			stub: stub, helperCallOffset: helperCallOffset,
		})
	}
	return result, nil
}

func replacementShape(site Site) (start, length uint32, branch byte, err error) {
	branch = 0xe8
	switch site.Form {
	case FormCall64, FormCall32:
		length = 6
	case FormJump64, FormJump32:
		length, branch = 6, 0xe9
	case FormMove64:
		length = 7
	case FormMoveEAX:
		length = 5
	case FormMove32:
		length = 6
	default:
		return 0, 0, 0, fmt.Errorf("%w: %s", ErrInvalidRewritePlan, site.Form)
	}
	if site.Offset < length-4 {
		return 0, 0, 0, fmt.Errorf("%w: displacement %#x precedes a %d-byte instruction", ErrInvalidRewritePlan, site.Offset, length)
	}
	return site.Offset - (length - 4), length, branch, nil
}

type machineEncoder struct {
	data             []byte
	helperCallOffset uint32
}

func encodeStub(machine coff.Machine, site Site) ([]byte, uint32, error) {
	encoder := &machineEncoder{}
	move := site.Form == FormMove64 || site.Form == FormMoveEAX || site.Form == FormMove32
	encoder.byte(0x9c) // pushf[q/d]: preserve flags across the resolver helper.
	if machine == coff.MachineAMD64 {
		preserveAccumulator := move && site.Destination != "rax"
		if preserveAccumulator {
			encoder.bytes(0x50, 0x50) // upstream pushrax keeps 16-byte stack parity.
		}
		if err := encoder.resolve64(site.Invocation); err != nil {
			return nil, 0, err
		}
		if move {
			if preserveAccumulator {
				if err := encoder.moveRAX(site.Destination); err != nil {
					return nil, 0, err
				}
				encoder.bytes(0x58, 0x58)
			}
			encoder.bytes(0x9d, 0xc3) // popfq; ret
		} else {
			encoder.bytes(0x9d, 0xff, 0xe0) // popfq; jmp rax
		}
		return encoder.data, encoder.helperCallOffset, nil
	}
	if machine != coff.MachineI386 {
		return nil, 0, fmt.Errorf("%w: unsupported machine %s", ErrInvalidRewritePlan, machine)
	}
	preserveAccumulator := move && site.Destination != "eax"
	if preserveAccumulator {
		encoder.byte(0x50)
	}
	if err := encoder.resolve32(site.Invocation); err != nil {
		return nil, 0, err
	}
	if move {
		if preserveAccumulator {
			if err := encoder.moveEAX(site.Destination); err != nil {
				return nil, 0, err
			}
			encoder.byte(0x58)
		}
		encoder.bytes(0x9d, 0xc3) // popfd; ret
	} else {
		encoder.bytes(0x9d, 0xff, 0xe0) // popfd; jmp eax
	}
	return encoder.data, encoder.helperCallOffset, nil
}

func (e *machineEncoder) resolve64(invocation Invocation) error {
	// Match BaseModify.pushad: preserve the six volatile integer argument and
	// scratch registers that the resolver helper may overwrite.
	e.bytes(0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53)
	// Preserve RBP and use it to restore the exact incoming stack after a
	// dynamic 16-byte alignment and shadow-space allocation.
	e.bytes(0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xe4, 0xf0)
	if err := e.subRSP(invocation.FrameSize); err != nil {
		return err
	}
	if invocation.Method.IsHash() {
		e.byte(0xb9)
		e.uint32(invocation.ModuleHash)
		e.byte(0xba)
		e.uint32(invocation.FunctionHash)
	} else if invocation.Method.IsStrings() {
		if err := e.writeString64(invocation.ModuleOffset, invocation.ModuleString); err != nil {
			return err
		}
		if err := e.writeString64(invocation.FunctionOffset, invocation.FunctionString); err != nil {
			return err
		}
		e.leaRSP(1, invocation.ModuleOffset)   // rcx
		e.leaRSP(2, invocation.FunctionOffset) // rdx
	} else {
		return fmt.Errorf("%w: invalid invocation method %q", ErrInvalidRewritePlan, invocation.Method)
	}
	e.callPlaceholder()
	e.bytes(0x48, 0x89, 0xec, 0x5d) // mov rsp, rbp; pop rbp
	// Reverse BaseModify.pushad.
	e.bytes(0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5a, 0x59)
	return nil
}

func (e *machineEncoder) resolve32(invocation Invocation) error {
	e.bytes(0x51, 0x52) // push ecx; push edx
	if invocation.Method.IsHash() {
		e.byte(0x68)
		e.uint32(invocation.FunctionHash)
		e.byte(0x68)
		e.uint32(invocation.ModuleHash)
	} else if invocation.Method.IsStrings() {
		for _, value := range invocation.ModuleString.PushOrder {
			e.byte(0x68)
			e.uint32(value)
		}
		e.bytes(0x89, 0xe1) // mov ecx, esp
		for _, value := range invocation.FunctionString.PushOrder {
			e.byte(0x68)
			e.uint32(value)
		}
		e.bytes(0x89, 0xe2, 0x52, 0x51) // mov edx,esp; push edx; push ecx
	} else {
		return fmt.Errorf("%w: invalid invocation method %q", ErrInvalidRewritePlan, invocation.Method)
	}
	e.callPlaceholder()
	if err := e.addESP(invocation.CleanupSize); err != nil {
		return err
	}
	e.bytes(0x5a, 0x59) // pop edx; pop ecx
	return nil
}

func (e *machineEncoder) writeString64(base uint32, value StringData) error {
	for index, word := range value.Words {
		offset := uint64(base) + uint64(index)*8
		if offset > math.MaxInt32 {
			return fmt.Errorf("%w: string slot offset exceeds signed x64 displacement", ErrInvalidRewritePlan)
		}
		if word == 0 {
			e.storeByteRSP(uint32(offset), 0)
			continue
		}
		e.bytes(0x48, 0xb8)
		e.uint64(word)
		e.storeRAXToRSP(uint32(offset))
	}
	return nil
}

func (e *machineEncoder) subRSP(value uint32) error {
	if value == 0 {
		return fmt.Errorf("%w: x64 resolver frame is empty", ErrInvalidRewritePlan)
	}
	if value > math.MaxInt32 {
		return fmt.Errorf("%w: x64 resolver frame exceeds signed immediate range", ErrInvalidRewritePlan)
	}
	if value <= math.MaxInt8 {
		e.bytes(0x48, 0x83, 0xec, byte(value))
	} else {
		e.bytes(0x48, 0x81, 0xec)
		e.uint32(value)
	}
	return nil
}

func (e *machineEncoder) addESP(value uint32) error {
	if value == 0 {
		return fmt.Errorf("%w: x86 resolver cleanup is empty", ErrInvalidRewritePlan)
	}
	if value <= math.MaxInt8 {
		e.bytes(0x83, 0xc4, byte(value))
	} else {
		e.bytes(0x81, 0xc4)
		e.uint32(value)
	}
	return nil
}

func (e *machineEncoder) storeByteRSP(offset uint32, value byte) {
	switch {
	case offset == 0:
		e.bytes(0xc6, 0x04, 0x24, value)
	case offset <= math.MaxInt8:
		e.bytes(0xc6, 0x44, 0x24, byte(offset), value)
	default:
		e.bytes(0xc6, 0x84, 0x24)
		e.uint32(offset)
		e.byte(value)
	}
}

func (e *machineEncoder) storeRAXToRSP(offset uint32) {
	switch {
	case offset == 0:
		e.bytes(0x48, 0x89, 0x04, 0x24)
	case offset <= math.MaxInt8:
		e.bytes(0x48, 0x89, 0x44, 0x24, byte(offset))
	default:
		e.bytes(0x48, 0x89, 0x84, 0x24)
		e.uint32(offset)
	}
}

func (e *machineEncoder) leaRSP(register byte, offset uint32) {
	reg := (register & 7) << 3
	switch {
	case offset == 0:
		e.bytes(0x48, 0x8d, reg|0x04, 0x24)
	case offset <= math.MaxInt8:
		e.bytes(0x48, 0x8d, reg|0x44, 0x24, byte(offset))
	default:
		e.bytes(0x48, 0x8d, reg|0x84, 0x24)
		e.uint32(offset)
	}
}

func (e *machineEncoder) moveRAX(destination string) error {
	register := registerIndex64(destination)
	if register < 0 || register == 4 {
		return fmt.Errorf("%w: cannot move resolver result to %s", ErrInvalidRewritePlan, destination)
	}
	rex := byte(0x48)
	if register >= 8 {
		rex |= 0x01
	}
	e.bytes(rex, 0x89, 0xc0|byte(register&7))
	return nil
}

func (e *machineEncoder) moveEAX(destination string) error {
	register := registerIndex32(destination)
	if register < 0 || register == 4 {
		return fmt.Errorf("%w: cannot move resolver result to %s", ErrInvalidRewritePlan, destination)
	}
	e.bytes(0x89, 0xc0|byte(register))
	return nil
}

func (e *machineEncoder) callPlaceholder() {
	e.byte(0xe8)
	e.helperCallOffset = uint32(len(e.data))
	e.uint32(0)
}

func (e *machineEncoder) byte(value byte)      { e.data = append(e.data, value) }
func (e *machineEncoder) bytes(values ...byte) { e.data = append(e.data, values...) }
func (e *machineEncoder) uint32(value uint32) {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	e.data = append(e.data, data[:]...)
}
func (e *machineEncoder) uint64(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	e.data = append(e.data, data[:]...)
}

func registerIndex64(name string) int {
	for index := 0; index < 16; index++ {
		if register64(index) == name {
			return index
		}
	}
	return -1
}

func registerIndex32(name string) int {
	for index := 0; index < 8; index++ {
		if register32(index) == name {
			return index
		}
	}
	return -1
}

func reserveStubSectionName(object *coff.Object) string {
	base := ".text$cpl_dfr"
	name := base
	for suffix := 1; ; suffix++ {
		if object.GetSection(name) == nil && object.GetSymbol(name) == nil {
			return name
		}
		name = fmt.Sprintf("%s$%d", base, suffix)
	}
}
