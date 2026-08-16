// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package resolver

import (
	"errors"
	"fmt"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

// ErrUnsupportedForm identifies an import-bearing instruction/addressing form
// that upstream ResolveAPI cannot safely replace through this port boundary.
var ErrUnsupportedForm = errors.New("resolver: unsupported instruction or addressing form")

// Form is one exact upstream ResolveAPI instruction form.
type Form string

const (
	FormCall64  Form = "CALL r/m64"
	FormJump64  Form = "JMP r/m64"
	FormMove64  Form = "MOV r64, r/m64"
	FormCall32  Form = "CALL r/m32"
	FormJump32  Form = "JMP r/m32"
	FormMoveEAX Form = "MOV EAX, moffs32"
	FormMove32  Form = "MOV r32, r/m32"
)

// Site is one validated import relocation and its selected resolver contract.
// Indices refer to the object supplied to BuildPlan and to the structurally
// identical clone passed to RewriteBackend.
type Site struct {
	SectionIndex    int
	RelocationIndex int
	SectionName     string
	Offset          uint32
	Symbol          string
	Form            Form
	Destination     string
	StubSymbol      string
	Import          Import
	Resolver        Resolver
	Invocation      Invocation
}

// RewritePlan lists resolver sites in COFF section/relocation order.
type RewritePlan struct {
	Machine coff.Machine
	Sites   []Site
}

// SiteError adds deterministic COFF location context to planning failures.
type SiteError struct {
	Section    string
	Relocation int
	Symbol     string
	Err        error
}

func (e *SiteError) Error() string {
	return fmt.Sprintf("resolver: section %s relocation %d symbol %q: %v", e.Section, e.Relocation, e.Symbol, e.Err)
}

func (e *SiteError) Unwrap() error { return e.Err }

// BuildPlan validates resolver selection, relocation bounds/types, and the raw
// encodings of every import-bearing executable instruction. It never mutates
// object or configuration.
func BuildPlan(object *coff.Object, configuration Configuration) (RewritePlan, error) {
	if object == nil {
		return RewritePlan{}, errors.New("resolver: nil COFF object")
	}
	if object.Machine != coff.MachineI386 && object.Machine != coff.MachineAMD64 {
		return RewritePlan{}, fmt.Errorf("resolver: unsupported machine %s", object.Machine)
	}
	plan := RewritePlan{Machine: object.Machine}
	if !configuration.HasResolvers() {
		return plan, nil
	}

	reservedSymbols := make(map[string]struct{}, len(object.Symbols))
	for _, symbol := range object.Symbols {
		if symbol != nil {
			reservedSymbols[symbol.Name] = struct{}{}
		}
	}
	for sectionIndex, section := range object.Sections {
		if section == nil {
			return RewritePlan{}, fmt.Errorf("resolver: section %d is nil", sectionIndex)
		}
		if !section.IsExecutable() {
			continue
		}
		for relocationIndex, relocation := range section.Relocations {
			if relocation == nil {
				return RewritePlan{}, &SiteError{Section: section.Name, Relocation: relocationIndex, Err: errors.New("nil relocation")}
			}
			imported, ok := ParseImport(relocation.SymbolName)
			if !ok {
				continue
			}
			siteError := func(err error) error {
				return &SiteError{Section: section.Name, Relocation: relocationIndex, Symbol: relocation.SymbolName, Err: err}
			}
			if relocation.Section != section {
				return RewritePlan{}, siteError(errors.New("relocation parent does not match containing section"))
			}
			if uint64(relocation.VirtualAddress)+4 > uint64(len(section.Data)) {
				return RewritePlan{}, siteError(fmt.Errorf("DWORD operand at %#x exceeds %d-byte section", relocation.VirtualAddress, len(section.Data)))
			}
			imported, err := imported.WithRequiredModule()
			if err != nil {
				return RewritePlan{}, siteError(err)
			}
			selected, err := configuration.Resolve(imported)
			if err != nil {
				return RewritePlan{}, siteError(err)
			}
			if err := validateResolverFunction(object, selected.Function); err != nil {
				return RewritePlan{}, siteError(err)
			}
			form, destination, err := classify(object.Machine, section.Data, relocation)
			if err != nil {
				return RewritePlan{}, siteError(err)
			}
			invocation, err := BuildInvocation(object.Machine, imported, selected)
			if err != nil {
				return RewritePlan{}, siteError(err)
			}
			stubSymbol := reserveStubSymbol(reservedSymbols, len(plan.Sites))
			plan.Sites = append(plan.Sites, Site{
				SectionIndex: sectionIndex, RelocationIndex: relocationIndex,
				SectionName: section.Name, Offset: relocation.VirtualAddress,
				Symbol: relocation.SymbolName, Form: form, Destination: destination, StubSymbol: stubSymbol,
				Import: imported, Resolver: selected, Invocation: invocation,
			})
		}
	}
	return plan, nil
}

func classify(machine coff.Machine, code []byte, relocation *coff.Relocation) (Form, string, error) {
	offset := int(relocation.VirtualAddress)
	if machine == coff.MachineAMD64 {
		if relocation.Type != coff.RelAMD64Rel32 {
			return "", "", fmt.Errorf("%w: x64 import relocation type %#x", ErrUnsupportedForm, relocation.Type)
		}
		if offset >= 2 && code[offset-2] == 0xff {
			switch code[offset-1] {
			case 0x15:
				return FormCall64, "rax", nil
			case 0x25:
				return FormJump64, "rax", nil
			}
		}
		if offset >= 3 {
			rex, opcode, modrm := code[offset-3], code[offset-2], code[offset-1]
			if rex >= 0x48 && rex <= 0x4f && rex&0x08 != 0 && opcode == 0x8b && modrm&0xc7 == 0x05 {
				register := int((modrm>>3)&7) | int(rex&4)<<1
				if register == 4 {
					return "", "", fmt.Errorf("%w: MOV into RSP cannot preserve the resolver stack", ErrUnsupportedForm)
				}
				return FormMove64, register64(register), nil
			}
		}
		return "", "", fmt.Errorf("%w at displacement %#x; expected FF/2, FF/4, or REX.W 8B RIP-relative", ErrUnsupportedForm, offset)
	}

	if relocation.Type != coff.RelI386Dir32 {
		return "", "", fmt.Errorf("%w: x86 import relocation type %#x", ErrUnsupportedForm, relocation.Type)
	}
	if offset >= 2 && code[offset-2] == 0xff {
		switch code[offset-1] {
		case 0x15:
			return FormCall32, "eax", nil
		case 0x25:
			return FormJump32, "eax", nil
		}
	}
	if offset >= 1 && code[offset-1] == 0xa1 {
		return FormMoveEAX, "eax", nil
	}
	if offset >= 2 && code[offset-2] == 0x8b && code[offset-1]&0xc7 == 0x05 {
		register := int((code[offset-1] >> 3) & 7)
		if register == 4 {
			return "", "", fmt.Errorf("%w: MOV into ESP cannot preserve the resolver stack", ErrUnsupportedForm)
		}
		if register != 0 {
			return FormMove32, register32(register), nil
		}
	}
	return "", "", fmt.Errorf("%w at address operand %#x; expected FF/2, FF/4, A1, or non-EAX 8B absolute", ErrUnsupportedForm, offset)
}

func reserveStubSymbol(reserved map[string]struct{}, site int) string {
	base := fmt.Sprintf("__cpl_dfr_%08x", site)
	name := base
	for suffix := 1; ; suffix++ {
		if _, exists := reserved[name]; !exists {
			reserved[name] = struct{}{}
			return name
		}
		name = fmt.Sprintf("%s_%d", base, suffix)
	}
}

func register64(index int) string {
	registers := [...]string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
	if index < 0 || index >= len(registers) {
		return ""
	}
	return registers[index]
}

func register32(index int) string {
	registers := [...]string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"}
	if index < 0 || index >= len(registers) {
		return ""
	}
	return registers[index]
}
