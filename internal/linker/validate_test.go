// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package linker

import (
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestLinkerRejectsMalformedModelsWithoutPanicking(t *testing.T) {
	t.Run("nil relocation", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		text.Relocations = []*coff.Relocation{nil}
		if _, err := EmitPIC(object, PICOptions{}); err == nil || !strings.Contains(err.Error(), "relocation 0 is nil") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("wrong relocation parent", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 4)
		other := coff.NewSection("other", make([]byte, 4))
		text.Relocations = []*coff.Relocation{{Section: other, SymbolName: "target"}}
		if _, err := EmitPICO(object, PICOOptions{}); err == nil || !strings.Contains(err.Error(), "parent") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("wrong section owner", func(t *testing.T) {
		object := testObject(t, coff.MachineAMD64)
		text := testSection(t, object, ".text", 1)
		text.Object = nil
		if _, err := Merge(object); err == nil || !strings.Contains(err.Error(), "owner") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported merge machine", func(t *testing.T) {
		object := testObject(t, coff.MachineARM64)
		if _, err := Merge(object); err == nil || !strings.Contains(err.Error(), "unsupported machine") {
			t.Fatalf("error = %v", err)
		}
	})
}
