// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"bytes"
	"context"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
)

func TestApplyOrderTransformsPassesCatchHandlerRoots(t *testing.T) {
	object := textObject(t, coff.MachineAMD64, []byte{0xc3, 0xc3, 0xc3},
		function("go", 0), function("handler", 1), function("dead", 2))
	artifact := newArtifact(KindObject, object)
	artifact.addOptions([]string{"+optimize"})
	directive, err := hooks.Parse("catch", []string{"go", "handler"})
	if err != nil {
		t.Fatal(err)
	}
	artifact.config.hooks, err = artifact.config.hooks.Apply(context.Background(), object, directive, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := New().applyOrderTransforms(artifact, object); err != nil {
		t.Fatal(err)
	}
	if object.GetSymbol("handler") == nil {
		t.Fatal("configured catch handler was optimized away")
	}
	if object.GetSymbol("dead") != nil {
		t.Fatal("unreachable non-handler function was retained")
	}
}

func TestApplyOrderTransformsDiscoPreservesFirstOnlyForRawPIC(t *testing.T) {
	for _, test := range []struct {
		name       string
		kind       Kind
		options    []string
		entryStart uint32
		wantEntry  uint32
	}{
		{name: "pic", kind: KindPIC, options: []string{"+gofirst", "+disco"}, entryStart: 1, wantEntry: 0},
		{name: "pic64", kind: KindPIC64, options: []string{"+disco"}, entryStart: 0, wantEntry: 0},
		{name: "pico", kind: KindObject, options: []string{"+gofirst", "+disco"}, entryStart: 1, wantEntry: 2},
		{name: "coff", kind: KindCOFF, options: []string{"+gofirst", "+disco"}, entryStart: 1, wantEntry: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var object *coff.Object
			if test.entryStart == 0 {
				object = textObject(t, coff.MachineAMD64, []byte{0xc3, 0xcc, 0x90},
					function("go", 0), function("helper", 1), function("third", 2))
			} else {
				object = textObject(t, coff.MachineAMD64, []byte{0xcc, 0xc3, 0x90},
					function("helper", 0), function("go", 1), function("third", 2))
			}
			artifact := newArtifact(test.kind, object)
			artifact.addOptions(test.options)
			handler := New()
			handler.random = bytes.NewReader(make([]byte, 32))
			if err := handler.applyOrderTransforms(artifact, object); err != nil {
				t.Fatal(err)
			}
			if got := object.GetSymbol("go").Value; got != test.wantEntry {
				t.Fatalf("go offset = %d, want %d", got, test.wantEntry)
			}
		})
	}
}
