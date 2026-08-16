// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package coff

import (
	"fmt"
	"strings"
)

// Visitor provides deterministic object-order traversal. A nil callback is
// ignored, which makes focused linker and diagnostic visitors inexpensive.
type Visitor struct {
	Section    func(*Section) error
	Relocation func(*Section, *Relocation) error
	Symbol     func(*Symbol) error
}

func (o *Object) Walk(visitor Visitor) error {
	for _, section := range o.Sections {
		if visitor.Section != nil {
			if err := visitor.Section(section); err != nil {
				return err
			}
		}
		if visitor.Relocation != nil {
			for _, relocation := range section.Relocations {
				if err := visitor.Relocation(section, relocation); err != nil {
					return err
				}
			}
		}
	}
	if visitor.Symbol != nil {
		for _, symbol := range o.Symbols {
			if err := visitor.Symbol(symbol); err != nil {
				return err
			}
		}
	}
	return nil
}

// String renders a stable coffparse-oriented diagnostic representation.
func (o *Object) String() string {
	if o == nil {
		return "<nil COFF object>\n"
	}
	var output strings.Builder
	fmt.Fprintf(&output, "COFF Object (%s)\n", o.Architecture())
	fmt.Fprintf(&output, "Symbols (%d):\n", len(o.Symbols))
	for index, symbol := range o.Symbols {
		section := ""
		if symbol.Section != nil {
			section = symbol.Section.Name
		}
		fmt.Fprintf(&output, "  [%d] %s value=%#x section=%s type=%d class=%d size=%d\n", index, symbol.Name, symbol.Value, section, symbol.Type, symbol.StorageClass, symbol.EstimateSize())
	}
	fmt.Fprintf(&output, "Sections (%d):\n", len(o.Sections))
	for index, section := range o.Sections {
		fmt.Fprintf(&output, "  [%d] %s size=%d characteristics=%#x %s\n", index, section.Name, len(section.Data), section.Characteristics, FormatSectionFlags(section.Characteristics))
		for relocationIndex, relocation := range section.Relocations {
			offset, err := relocation.Offset()
			if err != nil {
				fmt.Fprintf(&output, "    relocation[%d] va=%#x symbol=%s type=%d offset=<invalid>\n", relocationIndex, relocation.VirtualAddress, relocation.SymbolName, relocation.Type)
			} else {
				fmt.Fprintf(&output, "    relocation[%d] va=%#x symbol=%s type=%d offset=%d\n", relocationIndex, relocation.VirtualAddress, relocation.SymbolName, relocation.Type, offset)
			}
		}
	}
	if rows, err := ParsePDATA(o); err == nil && len(rows) != 0 {
		fmt.Fprintf(&output, "PDATA (%d):\n", len(rows))
		for index, row := range rows {
			fmt.Fprintf(&output, "  [%d] begin=%#x end=%#x unwind=%#x function=%s\n", index, row.BeginAddress, row.EndAddress, row.UnwindData, row.Function)
			if row.Unwind != nil {
				fmt.Fprintf(&output, "    version=%d flags=%d prologue=%d codes=%d frame=%s+%d\n", row.Unwind.Version, row.Unwind.Flags, row.Unwind.SizeOfPrologue, row.Unwind.CountOfUnwindCodes, RegisterName(row.Unwind.FrameRegister), row.Unwind.FrameRegisterOffset)
				for codeIndex, code := range row.Unwind.Codes {
					fmt.Fprintf(&output, "    code[%d] offset=%d op=%s info=%d slots=%d value=%d\n", codeIndex, code.CodeOffset, code.OperationName(), code.OpInfo, code.Slots, code.Value)
				}
			}
		}
	}
	return output.String()
}
