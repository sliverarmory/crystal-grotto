// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package hooks

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	crystalhash "github.com/sliverarmory/crystal-grotto/internal/hash"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

// CallSite describes one decoded instruction and its associated relocation.
// InstructionString is used only for upstream-compatible diagnostics.
type CallSite struct {
	HasRelocation     bool
	Symbol            string
	Instruction       x86.Instruction
	InstructionString string
}

type ExpansionKind string

const (
	ExpansionResolveHooks  ExpansionKind = "resolve-hooks"
	ExpansionHashImmediate ExpansionKind = "hash-immediate"
	ExpansionUserBytes     ExpansionKind = "user-bytes"
)

// Expansion is a planned replacement for one relocation-bearing instruction.
// Bytes owns its storage. ResolvesRelocation is true for every successful
// intrinsic expansion.
type Expansion struct {
	Kind               ExpansionKind
	Symbol             string
	Bytes              []byte
	Immediate          uint32
	OriginalLength     int
	ResolvesRelocation bool
	RequiresRebuild    bool
	RequiresEncoder    bool
}

func (e Expansion) EncodingError() error {
	if !e.RequiresEncoder {
		return nil
	}
	return fmt.Errorf("%w: expand %s", ErrEncoderRequired, e.Symbol)
}

// ResolveROR13 implements the upstream named-hash and __tag_/___tag_
// intrinsic pass. It returns matched=false for unrelated sites.
func ResolveROR13(site CallSite) (Expansion, bool, error) {
	if !site.HasRelocation {
		return Expansion{}, false, nil
	}
	isNamedHash := crystalhash.MatchesPrefix(site.Symbol)
	isTag := strings.HasPrefix(site.Symbol, "__tag_") || strings.HasPrefix(site.Symbol, "___tag_")
	if !isNamedHash && !isTag {
		return Expansion{}, false, nil
	}
	if !isCallRel32(site.Instruction) {
		return Expansion{}, true, fmt.Errorf("Can't expand linker intrinsic %s for %s", site.Symbol, callSiteDescription(site))
	}
	var (
		value uint32
		err   error
	)
	if isNamedHash {
		value, err = crystalhash.ApplyIntrinsic(site.Symbol)
	} else {
		value = crystalhash.ROR13{}.Sum32([]byte(site.Symbol))
	}
	if err != nil {
		return Expansion{}, true, err
	}
	content := make([]byte, 5)
	content[0] = 0xb8 // mov eax, imm32 in both x86 modes
	binary.LittleEndian.PutUint32(content[1:], value)
	return Expansion{
		Kind: ExpansionHashImmediate, Symbol: site.Symbol, Bytes: content,
		Immediate: value, OriginalLength: len(site.Instruction.Bytes),
		ResolvesRelocation: true,
		RequiresRebuild:    len(site.Instruction.Bytes) != len(content),
	}, true, nil
}

// UserIntrinsics is an immutable, defensive view of configured byte
// replacements.
type UserIntrinsics struct {
	values map[string][]byte
}

func (u UserIntrinsics) Lookup(symbol string) ([]byte, bool) {
	content, present := u.values[symbol]
	return append([]byte(nil), content...), present
}

func (u UserIntrinsics) Symbols() []string {
	result := make([]string, 0, len(u.values))
	for symbol := range u.values {
		result = append(result, symbol)
	}
	// Model.UserIntrinsics returns entries in no externally observable order;
	// Snapshot retains declaration order. Keep this API deterministic.
	sort.Strings(result)
	return result
}

// Resolve implements ResolveUserIntrinsics.
func (u UserIntrinsics) Resolve(site CallSite) (Expansion, bool, error) {
	if !site.HasRelocation {
		return Expansion{}, false, nil
	}
	content, present := u.values[site.Symbol]
	if !present {
		return Expansion{}, false, nil
	}
	if !isCallRel32(site.Instruction) {
		return Expansion{}, true, fmt.Errorf("Can't expand user-defined intrinsic %s for %s", site.Symbol, callSiteDescription(site))
	}
	content = append([]byte(nil), content...)
	return Expansion{
		Kind: ExpansionUserBytes, Symbol: site.Symbol, Bytes: content,
		OriginalLength: len(site.Instruction.Bytes), ResolvesRelocation: true,
		RequiresRebuild: len(site.Instruction.Bytes) != len(content),
	}, true, nil
}

// UserIntrinsics returns a defensive immutable resolver.
func (m *Model) UserIntrinsics() UserIntrinsics {
	result := UserIntrinsics{values: make(map[string][]byte)}
	if m == nil {
		return result
	}
	for symbol, content := range m.intrinsics {
		result.values[symbol] = append([]byte(nil), content...)
	}
	return result
}

// ResolveIntrinsic applies the upstream pass precedence: __resolve_hook first,
// built-in named hash/tag expansion second, and user-defined bytes third.
func (m *Model) ResolveIntrinsic(site CallSite) (Expansion, bool, error) {
	if m == nil {
		return Expansion{}, false, ErrNilModel
	}
	if site.HasRelocation && site.Symbol == m.resolveHookSymbol() {
		if !isCallRel32(site.Instruction) {
			return Expansion{}, true, fmt.Errorf("Can't expand linker intrinsic __resolve_hook() for %s", callSiteDescription(site))
		}
		return Expansion{
			Kind: ExpansionResolveHooks, Symbol: site.Symbol,
			OriginalLength: len(site.Instruction.Bytes), ResolvesRelocation: true,
			RequiresRebuild: true, RequiresEncoder: true,
		}, true, nil
	}
	if expansion, matched, err := ResolveROR13(site); matched || err != nil {
		return expansion, matched, err
	}
	return m.UserIntrinsics().Resolve(site)
}

func (m *Model) resolveHookSymbol() string {
	if m.machine == coff.MachineI386 {
		return "___resolve_hook"
	}
	return "__resolve_hook"
}

func isCallRel32(instruction x86.Instruction) bool {
	if instruction.Form == "CALL rel32" {
		return true
	}
	return len(instruction.Bytes) == 5 && instruction.Bytes[0] == 0xe8
}

func callSiteDescription(site CallSite) string {
	if site.InstructionString != "" {
		return site.InstructionString
	}
	if site.Instruction.Form != "" {
		return site.Instruction.Form
	}
	if assembly := site.Instruction.Assembly(); assembly != "" {
		return assembly
	}
	return fmt.Sprintf("% X", site.Instruction.Bytes)
}
