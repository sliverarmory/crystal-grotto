// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
	crystalhash "github.com/sliverarmory/crystal-grotto/internal/hash"
	"github.com/sliverarmory/crystal-grotto/internal/linker"
	"github.com/sliverarmory/crystal-grotto/internal/spec"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestHandlerExportsEveryObjectKind(t *testing.T) {
	t.Parallel()
	input := marshalTestObject(t, textObject(t, coff.MachineAMD64, []byte{0x90, 0xc3}, function("go", 0)))

	tests := []struct {
		kind  string
		check func(*testing.T, []byte)
	}{
		{
			kind: "pic",
			check: func(t *testing.T, output []byte) {
				t.Helper()
				if !bytes.Equal(output, []byte{0x90, 0xc3}) {
					t.Fatalf("PIC = %x, want 90c3", output)
				}
			},
		},
		{
			kind: "pic64",
			check: func(t *testing.T, output []byte) {
				t.Helper()
				if !bytes.Equal(output, []byte{0x90, 0xc3}) {
					t.Fatalf("PIC64 = %x, want 90c3", output)
				}
			},
		},
		{
			kind: "object",
			check: func(t *testing.T, output []byte) {
				t.Helper()
				header, err := linker.ParsePICOHeader(output)
				if err != nil {
					t.Fatal(err)
				}
				if header.CodeLength != 2 || header.EntryAddress != 0 {
					t.Fatalf("PICO header = %#v, want code length 2 and entry 0", header)
				}
			},
		},
		{
			kind: "coff",
			check: func(t *testing.T, output []byte) {
				t.Helper()
				object, err := coff.Parse(output)
				if err != nil {
					t.Fatal(err)
				}
				if text := object.GetSection(".text"); text == nil || !bytes.Equal(text.Data, []byte{0x90, 0xc3}) {
					t.Fatalf("COFF .text = %#v", text)
				}
				if symbol := object.GetSymbol("go"); symbol == nil || !symbol.IsFunction() || symbol.Value != 0 {
					t.Fatalf("COFF go symbol = %#v", symbol)
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.kind, func(t *testing.T) {
			t.Parallel()
			output := runEngineSpec(t, "x64", "x64:\n  push $INPUT\n  make "+test.kind+"\n  export\n", spec.Environment{"$INPUT": input}, New())
			test.check(t, output)
		})
	}
}

func TestArtifactExportRedeclarationMatchesUpstream(t *testing.T) {
	t.Parallel()
	artifact := newArtifact(KindObject, nil)
	if err := artifact.setExport(linker.Export{Symbol: "one", Tag: 0x100}); err != nil {
		t.Fatal(err)
	}
	if err := artifact.setExport(linker.Export{Symbol: "one", Tag: 0x100}); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("same export/tag redeclaration error = %v", err)
	}
	if err := artifact.setExport(linker.Export{Symbol: "one", Tag: 0x101}); err != nil {
		t.Fatalf("replacement export tag: %v", err)
	}
	if got := artifact.config.exports; len(got) != 1 || got[0].Symbol != "one" || got[0].Tag != 0x101 {
		t.Fatalf("replaced exports = %#v", got)
	}
	if err := artifact.setExport(linker.Export{Symbol: "two", Tag: 0x101}); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("cross-symbol tag collision error = %v", err)
	}
}

func TestHandlerCOFFCommandsRoundTrip(t *testing.T) {
	t.Parallel()
	object := textObject(t, coff.MachineAMD64, []byte{1, 2, 3, 4}, function("go", 0))
	data := coff.NewSection(".data", []byte{5, 6, 7, 8})
	if err := object.AddSection(data); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(coff.NewDataSymbol(data, "old_name", 0)); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(&coff.Symbol{Name: "callback", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}); err != nil {
		t.Fatal(err)
	}

	source := marshalTestObject(t, object)
	program := `x64:
  push $INPUT
  make coff
  remap "old_name" "renamed"
  patch "go" $PATCH
  strip "renamed"
  push $BLOB
  link "blob"
  push $CODE
  linkfunc "callback"
  export
`
	output := runEngineSpec(t, "x64", program, spec.Environment{
		"$INPUT": source,
		"$PATCH": []byte{9, 8, 7, 6},
		"$BLOB":  []byte{0xaa, 0xbb},
		"$CODE":  []byte{0xcc, 0xc3},
	}, New())

	parsed, err := coff.Parse(output)
	if err != nil {
		t.Fatal(err)
	}
	if text := parsed.GetSection(".text"); text == nil || !bytes.Equal(text.Data, []byte{9, 8, 7, 6, 0xcc, 0xc3}) {
		t.Fatalf(".text = %x, want 09080706ccc3", text.Data)
	}
	if rdata := parsed.GetSection(".rdata"); rdata == nil || !bytes.Equal(rdata.Data, []byte{0xaa, 0xbb}) {
		t.Fatalf(".rdata = %#v", rdata)
	}
	if symbol := parsed.GetSymbol("callback"); symbol == nil || symbol.Section != parsed.GetSection(".text") || !symbol.IsFunction() {
		t.Fatalf("callback = %#v, want defined function in .text", symbol)
	}
	if symbol := parsed.GetSymbol("blob"); symbol == nil || symbol.Section != parsed.GetSection(".rdata") {
		t.Fatalf("blob = %#v, want defined data in .rdata", symbol)
	}
	if symbol := parsed.GetSymbol("old_name"); symbol != nil {
		t.Fatalf("old_name unexpectedly remains: %#v", symbol)
	}
	if symbol := parsed.GetSymbol("renamed"); symbol != nil {
		t.Fatalf("stripped renamed symbol unexpectedly remains: %#v", symbol)
	}
}

func TestHandlerMergeAndMergeLibrary(t *testing.T) {
	t.Parallel()

	t.Run("merge", func(t *testing.T) {
		t.Parallel()
		base := marshalTestObject(t, textObject(t, coff.MachineAMD64, []byte{0x90, 0xc3}, function("go", 0)))
		additional := textObject(t, coff.MachineAMD64, []byte{0xcc, 0xc3}, function("helper", 0))
		additional.GetSection(".text").Name = ".text$helper"
		additional.GetSection(".text").OriginalName = ".text$helper"
		additional.GetSymbol(".text").Name = ".text$helper"
		additionalBytes := marshalTestObject(t, additional)
		output := runEngineSpec(t, "x64", `x64:
  push $BASE
  make coff
  push $MORE
  merge
  export
`, spec.Environment{"$BASE": base, "$MORE": additionalBytes}, New())
		parsed, err := coff.Parse(output)
		if err != nil {
			t.Fatal(err)
		}
		if text := parsed.GetSection(".text"); text == nil || !bytes.Equal(text.Data, []byte{0x90, 0xc3, 0xcc, 0xc3}) {
			t.Fatalf("merged .text = %#v", text)
		}
		if helper := parsed.GetSymbol("helper"); helper == nil || helper.Value != 2 {
			t.Fatalf("helper = %#v, want offset 2", helper)
		}
	})

	t.Run("mergelib", func(t *testing.T) {
		t.Parallel()
		directory := t.TempDir()
		baseObject := textObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, function("go", 0))
		undefined := &coff.Symbol{Name: "helper", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
		if err := baseObject.AddSymbol(undefined); err != nil {
			t.Fatal(err)
		}
		text := baseObject.GetSection(".text")
		text.Relocations = append(text.Relocations, &coff.Relocation{
			Section: text, VirtualAddress: 1, SymbolName: "helper", Symbol: undefined, Type: coff.RelAMD64Rel32,
		})
		libraryObject := textObject(t, coff.MachineAMD64, []byte{0xc3}, function("helper", 0))
		unreferenced := textObject(t, coff.MachineAMD64, []byte{0xcc, 0xc3}, function("also_merged", 0))
		unreferenced.GetSection(".text").Name = ".text$also_merged"
		unreferenced.GetSection(".text").OriginalName = ".text$also_merged"
		unreferenced.GetSymbol(".text").Name = ".text$also_merged"
		writeZIPMembers(t, filepath.Join(directory, "helpers.zip"), map[string][]byte{
			"helper.o":       marshalTestObject(t, libraryObject),
			"unreferenced.o": marshalTestObject(t, unreferenced),
		})

		output := runEngineSpecFile(t, filepath.Join(directory, "merge.spec"), "x64", `x64:
  push $BASE
  make coff
  mergelib "helpers.zip"
  export
`, spec.Environment{"$BASE": marshalTestObject(t, baseObject)}, New())
		parsed, err := coff.Parse(output)
		if err != nil {
			t.Fatal(err)
		}
		helper := parsed.GetSymbol("helper")
		if helper == nil || helper.Section != parsed.GetSection(".text") {
			t.Fatalf("library helper = %#v, want defined .text symbol", helper)
		}
		if len(parsed.GetSection(".text").Relocations) != 0 {
			t.Fatalf("same-section library relocation was not resolved: %#v", parsed.GetSection(".text").Relocations)
		}
		if symbol := parsed.GetSymbol("also_merged"); symbol == nil || symbol.Section != parsed.GetSection(".text") {
			t.Fatalf("unreferenced ZIP member was not merged: %#v", symbol)
		}
	})
}

func TestHandlerOrderOptionsAndUnsupportedConfiguration(t *testing.T) {
	t.Parallel()

	t.Run("relax", func(t *testing.T) {
		t.Parallel()
		object := refptrObject(t)
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make coff +relax
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		parsed, err := coff.Parse(output)
		if err != nil {
			t.Fatal(err)
		}
		text := parsed.GetSection(".text")
		if text == nil || len(text.Data) < 2 || text.Data[1] != 0x8d {
			t.Fatalf("relaxed .text = %#v", text)
		}
		if parsed.GetSymbol(".refptr.target") != nil || parsed.GetSection(".rdata$.refptr.target") != nil {
			t.Fatal("relaxed refptr artifacts remain")
		}
	})

	t.Run("relax rejects x86", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineI386, []byte{0xc3}, function("_go", 0))
		err := runEngineSpecError(t, "x86", `x86:
  push $INPUT
  make coff +relax
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		if !strings.Contains(err.Error(), "+relax is x64 only") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("gofirst", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64, []byte{0xcc, 0xc3, 0x90, 0xc3}, function("helper", 0), function("go", 2))
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic +gofirst
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		if !bytes.Equal(output, []byte{0x90, 0xc3, 0xcc, 0xc3}) {
			t.Fatalf("+gofirst output = %x", output)
		}
	})

	t.Run("optimize", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64, []byte{0x90, 0xc3, 0xcc, 0xc3}, function("go", 0), function("dead", 2))
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic +optimize
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		if !bytes.Equal(output, []byte{0x90, 0xc3}) {
			t.Fatalf("+optimize output = %x", output)
		}
	})

	t.Run("unwind leaf", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0))
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic +unwind
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		if !bytes.Equal(output, []byte{0xc3}) {
			t.Fatalf("+unwind leaf output = %x", output)
		}
	})

	t.Run("configuration-only hook directive", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0))
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  protect "go"
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		if !bytes.Equal(output, []byte{0xc3}) {
			t.Fatalf("protect-only output = %x", output)
		}
	})
}

func TestHandlerEasyPICFixes(t *testing.T) {
	t.Parallel()

	t.Run("x64 bss references", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64,
			[]byte{0x48, 0x8b, 0x05, 0, 0, 0, 0, 0xc3, 0xc3},
			function("go", 0), function("getbss", 8),
		)
		bss := coff.NewSection(".bss", make([]byte, 32))
		if err := object.AddSection(bss); err != nil {
			t.Fatal(err)
		}
		text := object.GetSection(".text")
		bssSymbol := object.GetSymbol(".bss")
		text.Relocations = []*coff.Relocation{{
			Section: text, VirtualAddress: 3, SymbolName: bssSymbol.Name,
			Symbol: bssSymbol, Type: coff.RelAMD64Rel32,
		}}

		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  fixbss "getbss"
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		want := []byte{
			0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
			0x48, 0x83, 0xec, 0x28, 0xb9, 0x20, 0, 0, 0, 0xe8, 0x12, 0, 0, 0,
			0x48, 0x83, 0xc4, 0x28, 0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,
			0x5a, 0x59, 0x48, 0x8b, 0, 0xc3, 0xc3,
		}
		if !bytes.Equal(output, want) {
			t.Fatalf("fixbss PIC = %x\nwant = %x", output, want)
		}
	})

	t.Run("command validation", func(t *testing.T) {
		t.Parallel()
		x64 := textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0))
		err := runEngineSpecError(t, "x64", "x64:\n  push $INPUT\n  make coff\n  fixbss \"go\"\n", spec.Environment{"$INPUT": marshalTestObject(t, x64)}, New())
		if !strings.Contains(err.Error(), "fixbss [symbol] is PIC-only") {
			t.Fatalf("fixbss error = %v", err)
		}

		x86 := textObject(t, coff.MachineI386, []byte{0xc3}, function("_go", 0))
		err = runEngineSpecError(t, "x86", "x86:\n  push $INPUT\n  make coff\n  fixptrs \"_go\"\n", spec.Environment{"$INPUT": marshalTestObject(t, x86)}, New())
		if !strings.Contains(err.Error(), "fixptrs [_symbol] is x86 PIC-only") {
			t.Fatalf("fixptrs error = %v", err)
		}
	})
}

func TestHandlerDynamicFunctionResolvers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		arch           string
		machine        coff.Machine
		entry          string
		resolver       string
		importName     string
		relocationType uint16
		method         string
	}{
		{
			name: "x64 ror13", arch: "x64", machine: coff.MachineAMD64,
			entry: "go", resolver: "resolve", importName: "__imp_KERNEL32$Sleep",
			relocationType: coff.RelAMD64Rel32, method: "ror13",
		},
		{
			name: "x86 strings", arch: "x86", machine: coff.MachineI386,
			entry: "_go", resolver: "_resolve", importName: "__imp__KERNEL32$Sleep@4",
			relocationType: coff.RelI386Dir32, method: "strings",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			object := textObject(t, test.machine,
				[]byte{0xff, 0x15, 0, 0, 0, 0, 0xc3, 0xc3},
				function(test.entry, 0), function(test.resolver, 7),
			)
			imported := &coff.Symbol{Name: test.importName, Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
			if err := object.AddSymbol(imported); err != nil {
				t.Fatal(err)
			}
			text := object.GetSection(".text")
			text.Relocations = []*coff.Relocation{{
				Section: text, VirtualAddress: 2, SymbolName: imported.Name,
				Symbol: imported, Type: test.relocationType,
			}}

			program := test.arch + ":\n  push $INPUT\n  make pic\n  dfr \"" + test.resolver + "\" \"" + test.method + "\"\n  export\n"
			output := runEngineSpec(t, test.arch, program, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
			if len(output) <= len(text.Data) || output[0] != 0x90 || output[1] != 0xe8 {
				t.Fatalf("resolver PIC prefix/length = %x (%d bytes)", output, len(output))
			}
			stub := int64(6) + int64(int32(binary.LittleEndian.Uint32(output[2:6])))
			if stub < int64(len(text.Data)) || stub+5 > int64(len(output)) || output[stub] != 0x9c {
				t.Fatalf("resolver stub target = %#x in %d-byte PIC (%x)", stub, len(output), output)
			}
		})
	}

	t.Run("clear replaces earlier default", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64,
			[]byte{0xff, 0x15, 0, 0, 0, 0, 0xc3, 0xc3, 0xc3},
			function("go", 0), function("first", 7), function("second", 8),
		)
		imported := &coff.Symbol{Name: "__imp_KERNEL32$Sleep", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
		if err := object.AddSymbol(imported); err != nil {
			t.Fatal(err)
		}
		text := object.GetSection(".text")
		text.Relocations = []*coff.Relocation{{
			Section: text, VirtualAddress: 2, SymbolName: imported.Name,
			Symbol: imported, Type: coff.RelAMD64Rel32,
		}}
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  dfr "first" "ror13"
  dfr "second" "djb2" +clear
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		if len(output) <= len(text.Data) {
			t.Fatalf("resolver output = %x", output)
		}
	})
}

func TestHandlerMutateOptionUsesConfiguredMagic(t *testing.T) {
	t.Parallel()
	object := textObject(t, coff.MachineAMD64,
		[]byte{0xb8, 0x44, 0x33, 0x22, 0x11, 0xc3},
		function("go", 0),
	)
	handler := New()
	handler.random = bytes.NewReader([]byte{0, 0, 0, 0})
	output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic +mutate
  magic "0x20"
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, handler)
	want := []byte{0xb8, 0x24, 0x33, 0x22, 0x11, 0x05, 0x20, 0, 0, 0, 0xc3}
	if !bytes.Equal(output, want) {
		t.Fatalf("mutated PIC = %x, want %x", output, want)
	}
}

func TestHandlerRegDanceOption(t *testing.T) {
	code := []byte{
		0x55, 0x53, 0x56, 0x57,
		0x89, 0xf3,
		0x8d, 0x7c, 0x5d, 0x10,
		0x01, 0xfe,
		0x5f, 0x5e, 0x5b, 0x5d, 0xc3, 0x90, 0x90, 0x90,
	}
	object := textObject(t, coff.MachineI386, code, function("_go", 0))
	handler := New()
	handler.random = bytes.NewReader(make([]byte, 64))
	output := runEngineSpec(t, "x86", `x86:
  push $INPUT
  make pic +regdance
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, handler)
	if bytes.Equal(output, code) || len(output) != len(code) {
		t.Fatalf("+regdance output = %x, input = %x", output, code)
	}
	if !bytes.Equal(output[:4], code[:4]) || !bytes.Equal(output[12:], code[12:]) {
		t.Fatalf("+regdance changed function bookends: %x", output)
	}
}

func TestHandlerStructuralTransformOptions(t *testing.T) {
	code := []byte{
		0x83, 0xf9, 0x00, 0x74, 0x07,
		0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x05,
		0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3,
		0x85, 0xd2, 0x75, 0x03, 0x31, 0xc0, 0xc3,
		0xb8, 0x03, 0x00, 0x00, 0x00, 0xc3, 0x90,
	}
	input := marshalTestObject(t, textObject(t, coff.MachineAMD64, code,
		function("go", 0), function("helper", 0x12)))
	run := func(options string) []byte {
		handler := New()
		handler.random = bytes.NewReader(make([]byte, 256))
		return runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic `+options+`
  export
`, spec.Environment{"$INPUT": input}, handler)
	}

	blockOutput := run("+blockparty")
	if bytes.Equal(blockOutput, code) {
		t.Fatal("+blockparty left the eligible input unchanged")
	}
	shatterOutput := run("+shatter")
	if bytes.Equal(shatterOutput, code) {
		t.Fatal("+shatter left the eligible input unchanged")
	}
	if both := run("+blockparty +shatter"); !bytes.Equal(both, shatterOutput) {
		t.Fatalf("+shatter did not take precedence over +blockparty\nboth:    %x\nshatter: %x", both, shatterOutput)
	}
}

func TestHandlerGeneratedUnwindOutputs(t *testing.T) {
	object := textObject(t, coff.MachineAMD64, []byte{0x55, 0x5d, 0xc3}, function("go", 0))
	if err := object.AddSymbol(&coff.Symbol{Name: "unwind_resource", StorageClass: coff.SymbolClassExternal}); err != nil {
		t.Fatal(err)
	}
	input := marshalTestObject(t, object)

	t.Run("COFF sections", func(t *testing.T) {
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make coff +unwind
  export
`, spec.Environment{"$INPUT": input}, New())
		parsed, err := coff.Parse(output)
		if err != nil {
			t.Fatal(err)
		}
		pdata := parsed.GetSection(".pdata")
		var xdata *coff.Section
		for _, section := range parsed.Sections {
			if strings.HasPrefix(section.Name, ".xdata") {
				xdata = section
				break
			}
		}
		if pdata == nil || xdata == nil || len(pdata.Data) != 12 || len(xdata.Data) != 8 {
			t.Fatalf("generated unwind sections = %#v, %#v", pdata, xdata)
		}
		rows, err := coff.ParsePDATA(parsed)
		if err != nil || len(rows) != 1 || rows[0].Function != "go" {
			t.Fatalf("parsed unwind rows = %#v, %v", rows, err)
		}
	})

	t.Run("PICO resource", func(t *testing.T) {
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make object +unwind
  export
`, spec.Environment{"$INPUT": input}, New())
		header, err := linker.ParsePICOHeader(output)
		if err != nil {
			t.Fatal(err)
		}
		if header.CodeLength <= 3 || header.ResourceOffset < linker.PICOHeaderSize {
			t.Fatalf("PICO unwind header = %#v", header)
		}
		directives, err := linker.DecodeDirectives(output[linker.PICOHeaderSize:header.ResourceOffset])
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, directive := range directives {
			if directive.Type == linker.PICOInstructionExport && len(directive.Data) >= 8 && binary.LittleEndian.Uint32(directive.Data[:4]) == linker.PICOUnwindExportTag {
				found = true
			}
		}
		if !found {
			t.Fatalf("PICO directives omit unwind export: %#v", directives)
		}
	})

	t.Run("PIC linkpost resource", func(t *testing.T) {
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  linkpost "unwind_resource" "unwind"
  export
`, spec.Environment{"$INPUT": input}, New())
		if len(output) != 32 || !bytes.Equal(output[:3], []byte{0x55, 0x5d, 0xc3}) {
			t.Fatalf("PIC linkpost output = %x", output)
		}
		if got := binary.LittleEndian.Uint32(output[4:8]); got != 12 {
			t.Fatalf("PIC linkpost pdata length = %d", got)
		}
		if got := binary.LittleEndian.Uint32(output[16:20]); got != 24 {
			t.Fatalf("PIC linkpost xdata address = %#x, want %#x", got, 24)
		}
	})

	t.Run("linkpost symbol may be introduced later", func(t *testing.T) {
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  linkpost "late_resource" "unwind"
  remap "unwind_resource" "late_resource"
  export
`, spec.Environment{"$INPUT": input}, New())
		if len(output) != 32 || !bytes.Equal(output[:3], []byte{0x55, 0x5d, 0xc3}) {
			t.Fatalf("deferred linkpost output = %x", output)
		}
	})
}

func TestHandlerRejectsDprintfReachableFromResolver(t *testing.T) {
	t.Parallel()
	object := textObject(t, coff.MachineAMD64,
		[]byte{0xc3, 0xe8, 0, 0, 0, 0, 0xc3, 0xc3},
		function("go", 0), function("resolve", 1), function("dprintf", 7),
	)
	text := object.GetSection(".text")
	dprintf := object.GetSymbol("dprintf")
	text.Relocations = []*coff.Relocation{{
		Section: text, VirtualAddress: 2, SymbolName: dprintf.Name,
		Symbol: dprintf, Type: coff.RelAMD64Rel32,
	}}
	err := runEngineSpecError(t, "x64", `x64:
  push $INPUT
  make pic
  dfr "resolve" "ror13"
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
	if !strings.Contains(err.Error(), "Don't call dprintf from dfr/fixptrs/fixbss") ||
		!strings.Contains(err.Error(), "resolve") {
		t.Fatalf("DangerWalk error = %v", err)
	}
}

func TestHandlerISEDValidatesAndRetainsResolvedBytes(t *testing.T) {
	t.Parallel()
	object := textObject(t, coff.MachineAMD64, []byte{0x53, 0x5b, 0xc3}, function("go", 0))
	output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  ised replace "PUSH r64" $CODE +first
  export
`, spec.Environment{
		"$INPUT": marshalTestObject(t, object),
		"$CODE":  []byte{0x90},
	}, New())
	if want := []byte{0x90, 0x5b, 0xc3}; !bytes.Equal(output, want) {
		t.Fatalf("ised output = %x, want %x", output, want)
	}
	output = runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  ised replace "PUSH r64" $CODE +first +split
  export
`, spec.Environment{
		"$INPUT": marshalTestObject(t, object),
		"$CODE":  []byte{0x90},
	}, New())
	if want := []byte{0x90, 0x5b, 0xc3}; !bytes.Equal(output, want) {
		t.Fatalf("ised +split healed output = %x, want %x", output, want)
	}

	err := runEngineSpecError(t, "x64", `x64:
  push $INPUT
  make pic
  ised replace "PUSH r64" $MISSING
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
	if !strings.Contains(err.Error(), "$MISSING") {
		t.Fatalf("ised missing byte variable error = %v", err)
	}
}

func TestHandlerHookEncoding(t *testing.T) {
	t.Parallel()

	t.Run("attach import", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64,
			[]byte{0xff, 0x15, 0, 0, 0, 0, 0xc3, 0xc3},
			function("go", 0), function("wrapper", 7),
		)
		imported := &coff.Symbol{Name: "__imp_KERNEL32$Sleep", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
		if err := object.AddSymbol(imported); err != nil {
			t.Fatal(err)
		}
		text := object.GetSection(".text")
		text.Relocations = []*coff.Relocation{{
			Section: text, VirtualAddress: 2, SymbolName: imported.Name,
			Symbol: imported, Type: coff.RelAMD64Rel32,
		}}
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  attach "KERNEL32$Sleep" "wrapper"
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		if want := []byte{0x90, 0xe8, 1, 0, 0, 0, 0xc3, 0xc3}; !bytes.Equal(output, want) {
			t.Fatalf("attach output = %x, want %x", output, want)
		}
	})

	t.Run("redirect local call", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3, 0xc3, 0xc3},
			function("go", 0), function("target", 6), function("wrapper", 7),
		)
		text := object.GetSection(".text")
		target := object.GetSymbol("target")
		text.Relocations = []*coff.Relocation{{
			Section: text, VirtualAddress: 1, SymbolName: target.Name,
			Symbol: target, Type: coff.RelAMD64Rel32,
		}}
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  redirect "target" "wrapper"
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		if want := []byte{0xe8, 2, 0, 0, 0, 0xc3, 0xc3, 0xc3}; !bytes.Equal(output, want) {
			t.Fatalf("redirect output = %x, want %x", output, want)
		}
	})

	t.Run("intrinsic bytes are resolved and retained", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, function("go", 0))
		intrinsic := &coff.Symbol{Name: "__custom", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
		if err := object.AddSymbol(intrinsic); err != nil {
			t.Fatal(err)
		}
		text := object.GetSection(".text")
		text.Relocations = []*coff.Relocation{{
			Section: text, VirtualAddress: 1, SymbolName: intrinsic.Name,
			Symbol: intrinsic, Type: coff.RelAMD64Rel32,
		}}
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  intrinsic "__custom" $CODE
  export
		`, spec.Environment{"$INPUT": marshalTestObject(t, object), "$CODE": []byte{0x31, 0xc0, 0x90, 0x90, 0xc3}}, New())
		if want := []byte{0x31, 0xc0, 0x90, 0x90, 0xc3, 0xc3}; !bytes.Equal(output, want) {
			t.Fatalf("intrinsic output = %x, want %x", output, want)
		}
	})

	t.Run("length-changing intrinsic bytes are rebuilt", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, function("go", 0))
		intrinsic := &coff.Symbol{Name: "__custom", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
		if err := object.AddSymbol(intrinsic); err != nil {
			t.Fatal(err)
		}
		text := object.GetSection(".text")
		text.Relocations = []*coff.Relocation{{
			Section: text, VirtualAddress: 1, SymbolName: intrinsic.Name,
			Symbol: intrinsic, Type: coff.RelAMD64Rel32,
		}}
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  intrinsic "__custom" $CODE
  export
		`, spec.Environment{"$INPUT": marshalTestObject(t, object), "$CODE": []byte{0xb8, 0x2a, 0, 0, 0, 0x90}}, New())
		if want := []byte{0xb8, 0x2a, 0, 0, 0, 0x90, 0xc3}; !bytes.Equal(output, want) {
			t.Fatalf("length-changing intrinsic output = %x, want %x", output, want)
		}
	})

	t.Run("transfer intrinsic emits the containing epilogue", func(t *testing.T) {
		t.Parallel()
		code := []byte{
			0x53, 0x56, 0x48, 0x83, 0xec, 0x28,
			0xe8, 0, 0, 0, 0, 0x90, 0xc3,
		}
		object := textObject(t, coff.MachineAMD64, code, function("go", 0))
		intrinsic := &coff.Symbol{Name: "__transfer", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
		if err := object.AddSymbol(intrinsic); err != nil {
			t.Fatal(err)
		}
		text := object.GetSection(".text")
		text.Relocations = []*coff.Relocation{{
			Section: text, VirtualAddress: 7, SymbolName: intrinsic.Name,
			Symbol: intrinsic, Type: coff.RelAMD64Rel32,
		}}
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		want := []byte{
			0x53, 0x56, 0x48, 0x83, 0xec, 0x28,
			0x48, 0x83, 0xc4, 0x28, 0x5e, 0x5b, 0xff, 0xe1, 0xc3,
		}
		if !bytes.Equal(output, want) {
			t.Fatalf("transfer output = %x, want %x", output, want)
		}
	})

	t.Run("resolve hook intrinsic", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64,
			[]byte{0xe8, 0, 0, 0, 0, 0xc3, 0xb8, 0x2a, 0, 0, 0, 0xc3},
			function("go", 0), function("wrapper", 6),
		)
		intrinsic := &coff.Symbol{Name: "__resolve_hook", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
		if err := object.AddSymbol(intrinsic); err != nil {
			t.Fatal(err)
		}
		text := object.GetSection(".text")
		text.Relocations = []*coff.Relocation{{
			Section: text, VirtualAddress: 1, SymbolName: intrinsic.Name,
			Symbol: intrinsic, Type: coff.RelAMD64Rel32,
		}}
		output := runEngineSpec(t, "x64", `x64:
  push $INPUT
  make pic
  addhook "KERNEL32$Sleep" "wrapper"
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		hash := make([]byte, 4)
		binary.LittleEndian.PutUint32(hash, (crystalhash.ROR13{}).Sum32([]byte("Sleep")))
		if len(output) <= len(text.Data) || !bytes.Contains(output, hash) {
			t.Fatalf("resolve-hook output = %x", output)
		}
	})
}

func TestHandlerRunAndGenerateRules(t *testing.T) {
	t.Parallel()
	capability, err := spec.None("x64")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("bytes only", func(t *testing.T) {
		handler := New()
		program, err := spec.Parse("rules.spec", "x64:\n  push $DATA\n")
		if err != nil {
			t.Fatal(err)
		}
		result, err := program.RunAndGenerate(capability, spec.RunOptions{Environment: spec.Environment{"$DATA": []byte{1}}, Handler: handler})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result.Program, []byte{1}) || len(result.Rules) != 0 {
			t.Fatalf("result = %#v", result)
		}
	})

	t.Run("object without rule", func(t *testing.T) {
		handler := New()
		object := marshalTestObject(t, textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)))
		program, err := spec.Parse("rules.spec", "x64:\n  push $INPUT\n  make pic\n  export\n")
		if err != nil {
			t.Fatal(err)
		}
		result, err := program.RunAndGenerate(capability, spec.RunOptions{Environment: spec.Environment{"$INPUT": object}, Handler: handler})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rules) != 0 {
			t.Fatalf("rules = %x, want empty", result.Rules)
		}
	})

	t.Run("warnings reach execution logger", func(t *testing.T) {
		handler := New()
		handler.ruleOptions.UUID = func() (string, error) { return "12345678-1234-4234-8234-123456789abc", nil }
		object := marshalTestObject(t, textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)))
		program, err := spec.Parse("warnings.spec", `x64:
  push $INPUT
  make pic
  rule "sample" 10 5 "10-16" "missing"
  export
`)
		if err != nil {
			t.Fatal(err)
		}
		var messages []spec.Message
		result, err := program.RunAndGenerate(capability, spec.RunOptions{
			Environment: spec.Environment{"$INPUT": object},
			Handler:     handler,
			Logger: spec.LoggerFunc(func(message spec.Message) {
				messages = append(messages, message)
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rules) != 0 || len(messages) != 1 {
			t.Fatalf("rules = %q, messages = %#v", result.Rules, messages)
		}
		if messages[0].Type != spec.MessageWarning || messages[0].Text != "sample_12345678: No invariant islands matching Yara rule generator criteria exist" {
			t.Fatalf("warning messages = %#v", messages)
		}
		for _, message := range messages {
			if message.File != "warnings.spec" || message.Target != "x64" {
				t.Fatalf("warning context = %#v", message)
			}
		}
	})

	t.Run("default arguments", func(t *testing.T) {
		handler := New()
		handler.ruleOptions.UUID = func() (string, error) { return "12345678-1234-4234-8234-123456789abc", nil }
		handler.ruleOptions.Clock = func() time.Time { return time.Date(2025, time.January, 2, 0, 0, 0, 0, time.UTC) }
		object := marshalTestObject(t, ruleObject(t))
		program, err := spec.Parse("rules.spec", "name \"Engine Rules\"\nx64:\n  push $INPUT\n  make pic\n  export\n")
		if err != nil {
			t.Fatal(err)
		}
		result, err := program.RunAndGenerate(capability, spec.RunOptions{Environment: spec.Environment{"$INPUT": object}, Handler: handler})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(result.Rules, []byte("rule Engine_Rules_12345678")) || !bytes.Contains(result.Rules, []byte("E8 ?? ?? ?? ??")) {
			t.Fatalf("generated rules =\n%s", result.Rules)
		}
	})

	t.Run("rule command overrides defaults but regular Run stays quiet", func(t *testing.T) {
		handler := New()
		handler.ruleOptions.UUID = func() (string, error) { return "abcdef01-1234-4234-8234-123456789abc", nil }
		object := marshalTestObject(t, ruleObject(t))
		program, err := spec.Parse("rules.spec", "x64:\n  push $INPUT\n  make pic\n  rule \"sample\" 1 1 \"3-16\"\n  export\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := program.Run(capability, spec.RunOptions{Environment: spec.Environment{"$INPUT": object}, Handler: handler}); err != nil {
			t.Fatal(err)
		}
		quiet, err := handler.GeneratedRules()
		if err != nil || len(quiet) != 0 {
			t.Fatalf("regular Run rules = %q, err=%v", quiet, err)
		}
		result, err := program.RunAndGenerate(capability, spec.RunOptions{Environment: spec.Environment{"$INPUT": object}, Handler: handler})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(result.Rules, []byte("rule sample_abcdef01")) || bytes.Count(result.Rules, []byte("$r")) != 1 {
			t.Fatalf("generated rules =\n%s", result.Rules)
		}
	})
}

func TestHandlerDiagnosticsAndValidation(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	coffReport := filepath.Join(directory, "coff.txt")
	disassembly := filepath.Join(directory, "disassembly.txt")
	object := marshalTestObject(t, textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)))
	handler := New()
	handler.newDisassembler = func(context.Context, coff.Machine) (x86.Disassembler, error) {
		return &fakeDisassembler{instructions: []x86.Instruction{{Address: 0, Bytes: []byte{0xc3}, Mnemonic: "ret", Form: "RET"}}}, nil
	}
	program := "x64:\n  push $INPUT\n  make pic\n  coffparse \"" + coffReport + "\" \"COFF report\"\n  disassemble \"" + disassembly + "\" \"Code\" +forms\n  export\n"
	runEngineSpec(t, "x64", program, spec.Environment{"$INPUT": object}, handler)

	coffContent, err := os.ReadFile(coffReport)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(coffContent, []byte("COFF report")) || !bytes.Contains(coffContent, []byte("COFF Object (x64)")) {
		t.Fatalf("coffparse output = %q", coffContent)
	}
	disassemblyContent, err := os.ReadFile(disassembly)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(disassemblyContent, []byte("Code")) || !bytes.Contains(disassemblyContent, []byte("ret")) || !bytes.Contains(disassemblyContent, []byte("; RET")) {
		t.Fatalf("disassembly output = %q", disassemblyContent)
	}

	tests := []struct {
		name    string
		arch    string
		object  *coff.Object
		program string
		env     spec.Environment
		want    string
	}{
		{
			name: "pic64 x86", arch: "x86",
			object:  textObject(t, coff.MachineI386, []byte{0xc3}, function("_go", 0)),
			program: "x86:\n  push $INPUT\n  make pic64\n  export\n", want: "make pic64 is x64-only",
		},
		{
			name: "architecture mismatch", arch: "x64",
			object:  textObject(t, coff.MachineI386, []byte{0xc3}, function("_go", 0)),
			program: "x64:\n  push $INPUT\n  make pic\n  export\n", want: "x86 COFF arch differs",
		},
		{
			name: "patch size", arch: "x64",
			object:  textObject(t, coff.MachineAMD64, []byte{1, 2, 3, 4}, function("go", 0)),
			program: "x64:\n  push $INPUT\n  make coff\n  patch \"go\" $PATCH\n  export\n", env: spec.Environment{"$PATCH": []byte{1}}, want: "size 4b differs from patch 1b",
		},
		{
			name: "linkfunc defined", arch: "x64",
			object:  textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)),
			program: "x64:\n  push $INPUT\n  make coff\n  push $CODE\n  linkfunc \"go\"\n  export\n", env: spec.Environment{"$CODE": []byte{0xc3}}, want: "Symbol go is already defined",
		},
		{
			name: "import on pic", arch: "x64",
			object:  textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)),
			program: "x64:\n  push $INPUT\n  make pic\n  import \"LoadLibraryA, GetProcAddress\"\n  export\n", want: "not a PICO",
		},
		{
			name: "bad import order", arch: "x64",
			object:  textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)),
			program: "x64:\n  push $INPUT\n  make object\n  import \"GetProcAddress, LoadLibraryA\"\n  export\n", want: "LoadLibraryA is required as the first API entry",
		},
		{
			name: "linkpost PICO", arch: "x64",
			object:  textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)),
			program: "x64:\n  push $INPUT\n  make object\n  linkpost \"unwind\" \"unwind\"\n", want: "linkpost is PIC-only",
		},
		{
			name: "linkpost key", arch: "x64",
			object:  textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)),
			program: "x64:\n  push $INPUT\n  make pic\n  linkpost \"resource\" \"unknown\"\n", want: "Invalid linkpost key",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			environment := test.env
			if environment == nil {
				environment = make(spec.Environment)
			}
			environment["$INPUT"] = marshalTestObject(t, test.object)
			err := runEngineSpecError(t, test.arch, test.program, environment, New())
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestHandlerDiagnosticsTruncateThenAppendCanonicalAliases(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	report := filepath.Join(directory, "combined.txt")
	alias := filepath.Join(directory, "combined-alias.txt")
	if err := os.WriteFile(report, []byte("stale diagnostic data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(report, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	first := filepath.Join(directory, "first.spec")
	second := filepath.Join(directory, "second.spec")
	if err := os.WriteFile(first, []byte("x64:\n  push $INPUT\n  make pic\n  coffparse \""+report+"\" \"first artifact\"\n  export\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("x64:\n  push $INPUT\n  make pic\n  coffparse \""+alias+"\" \"second artifact\"\n  export\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	object := marshalTestObject(t, textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)))
	runEngineSpecFile(t, filepath.Join(directory, "main.spec"), "x64", `x64:
  run "first.spec"
  pop $FIRST
  run "second.spec"
`, spec.Environment{"$INPUT": object}, New())

	content, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte("stale diagnostic data")) ||
		bytes.Count(content, []byte("COFF Object (x64)")) != 2 ||
		bytes.Index(content, []byte("first artifact")) >= bytes.Index(content, []byte("second artifact")) {
		t.Fatalf("combined diagnostic output = %q", content)
	}
	canonicalReport, err := filepath.EvalSymlinks(report)
	if err != nil {
		t.Fatal(err)
	}
	resolvedAlias, err := diagnosticOutput(alias)
	if err != nil {
		t.Fatal(err)
	}
	if resolvedAlias.Path != canonicalReport {
		t.Fatalf("canonical alias path = %q, want %q", resolvedAlias.Path, canonicalReport)
	}
}

func TestHandlerDiagnosticWritesAreConcurrentSafe(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "concurrent.txt")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := diagnosticOutput(path)
	if err != nil {
		t.Fatal(err)
	}
	handler := New()
	const writers = 24
	errors := make(chan error, writers)
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- handler.writeDiagnostic(output, []byte(fmt.Sprintf("[%02d]", index)))
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte("stale")) {
		t.Fatalf("first diagnostic write did not truncate: %q", content)
	}
	for index := 0; index < writers; index++ {
		token := []byte(fmt.Sprintf("[%02d]", index))
		if bytes.Count(content, token) != 1 {
			t.Fatalf("diagnostic token %q count in %q = %d, want 1", token, content, bytes.Count(content, token))
		}
	}

	var stdout bytes.Buffer
	handler.stdout = &stdout
	if err := handler.writeDiagnostic(&DiagnosticOutput{Stdout: true}, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := handler.writeDiagnostic(&DiagnosticOutput{Stdout: true}, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "onetwo" {
		t.Fatalf("STDOUT diagnostic = %q, want onetwo", stdout.String())
	}
}

func TestArtifactConfigurationIsDefensiveAndDeterministic(t *testing.T) {
	t.Parallel()
	artifact := newArtifact(KindObject, textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)))
	artifact.addOptions([]string{"+optimize", "+gofirst", "+optimize"})
	artifact.addStrip([]string{"z", "a", "z"})
	artifact.setPatch("go", []byte{1})
	artifact.setLink(linker.LinkedSection{Name: "blob", Data: []byte{2}, Relocations: []linker.LinkedRelocation{{SymbolName: ".text"}}})
	artifact.setLinkPost("post")
	artifact.config.getBSS = "getbss"
	artifact.config.returnAddress = "getret"
	artifact.deferCommand(DeferredCommand{Name: "protect", Arguments: []string{"go"}, AffectsProgram: true})

	configuration := artifact.Configuration()
	if got, want := strings.Join(configuration.Options, ","), "+gofirst,+optimize"; got != want {
		t.Fatalf("options = %q, want %q", got, want)
	}
	if got, want := strings.Join(configuration.Strip, ","), "a,z"; got != want {
		t.Fatalf("strip = %q, want %q", got, want)
	}
	configuration.Patches[0].Data[0] = 9
	configuration.Links[0].Data[0] = 9
	configuration.Links[0].Relocations[0].SymbolName = "changed"
	configuration.LinkPosts[0] = "changed"
	configuration.Deferred[0].Arguments[0] = "changed"
	again := artifact.Configuration()
	if again.Patches[0].Data[0] != 1 || again.Links[0].Data[0] != 2 || again.Deferred[0].Arguments[0] != "go" ||
		again.Links[0].Relocations[0].SymbolName != ".text" || again.LinkPosts[0] != "post" ||
		again.GetBSS != "getbss" || again.ReturnAddress != "getret" {
		t.Fatalf("Configuration exposed mutable storage: %#v", again)
	}
}

func TestHandlerCanServeIndependentExecutionsConcurrently(t *testing.T) {
	t.Parallel()
	input := marshalTestObject(t, textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)))
	program, err := spec.Parse("parallel.spec", "x64:\n  push $INPUT\n  make pic\n  export\n")
	if err != nil {
		t.Fatal(err)
	}
	capability, _ := spec.None("x64")
	const executions = 24
	var wait sync.WaitGroup
	errorsChannel := make(chan error, executions)
	for index := 0; index < executions; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			output, err := program.Run(capability, spec.RunOptions{Environment: spec.Environment{"$INPUT": input}, Handler: New()})
			if err != nil {
				errorsChannel <- err
				return
			}
			if !bytes.Equal(output, []byte{0xc3}) {
				errorsChannel <- errors.New("unexpected concurrent output")
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

type symbolSpec struct {
	name     string
	offset   uint32
	function bool
}

func function(name string, offset uint32) symbolSpec {
	return symbolSpec{name: name, offset: offset, function: true}
}

func textObject(t *testing.T, machine coff.Machine, code []byte, symbols ...symbolSpec) *coff.Object {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", code)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range symbols {
		var symbol *coff.Symbol
		if descriptor.function {
			symbol = coff.NewFunctionSymbol(text, descriptor.name, descriptor.offset)
		} else {
			symbol = coff.NewDataSymbol(text, descriptor.name, descriptor.offset)
		}
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
	}
	return object
}

func marshalTestObject(t *testing.T, object *coff.Object) []byte {
	t.Helper()
	data, err := coffwrite.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func runEngineSpec(t *testing.T, arch, content string, environment spec.Environment, handler *Handler) []byte {
	t.Helper()
	return runEngineSpecFile(t, "engine.spec", arch, content, environment, handler)
}

func runEngineSpecFile(t *testing.T, file, arch, content string, environment spec.Environment, handler *Handler) []byte {
	t.Helper()
	program, err := spec.Parse(file, content)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := spec.None(arch)
	if err != nil {
		t.Fatal(err)
	}
	output, err := program.Run(capability, spec.RunOptions{Environment: environment, Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func runEngineSpecError(t *testing.T, arch, content string, environment spec.Environment, handler *Handler) error {
	t.Helper()
	program, err := spec.Parse("engine.spec", content)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := spec.None(arch)
	if err != nil {
		t.Fatal(err)
	}
	_, err = program.Run(capability, spec.RunOptions{Environment: environment, Handler: handler})
	if err == nil {
		t.Fatal("Run unexpectedly succeeded")
	}
	return err
}

func refptrObject(t *testing.T) *coff.Object {
	t.Helper()
	object := textObject(t, coff.MachineAMD64, []byte{0x48, 0x8b, 0x05, 0, 0, 0, 0, 0xc3, 0xc3}, function("go", 0), function("target", 8))
	refptr := coff.NewSection(".rdata$.refptr.target", make([]byte, 8))
	if err := object.AddSection(refptr); err != nil {
		t.Fatal(err)
	}
	refptrSymbol := coff.NewDataSymbol(refptr, ".refptr.target", 0)
	if err := object.AddSymbol(refptrSymbol); err != nil {
		t.Fatal(err)
	}
	text := object.GetSection(".text")
	text.Relocations = append(text.Relocations, &coff.Relocation{
		Section: text, VirtualAddress: 3, SymbolName: refptrSymbol.Name, Symbol: refptrSymbol, Type: coff.RelAMD64Rel32,
	})
	return object
}

func ruleObject(t *testing.T) *coff.Object {
	t.Helper()
	return textObject(t, coff.MachineAMD64,
		[]byte{0xeb, 0x0e, 0x48, 0x8b, 0x05, 1, 2, 3, 4, 0xe8, 1, 0, 0, 0, 0x31, 0xc0, 0xc3},
		function("go", 0),
	)
}

func writeZIPMembers(t *testing.T, path string, members map[string][]byte) {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(members[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

type fakeDisassembler struct {
	instructions []x86.Instruction
	closed       bool
}

func (f *fakeDisassembler) Disassemble(context.Context, []byte, uint64) ([]x86.Instruction, error) {
	return append([]x86.Instruction(nil), f.instructions...), nil
}

func (f *fakeDisassembler) Close(context.Context) error {
	f.closed = true
	return nil
}
