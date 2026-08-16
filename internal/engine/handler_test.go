// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
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
		writeZIP(t, filepath.Join(directory, "helpers.zip"), "helper.o", marshalTestObject(t, libraryObject))

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
	})
}

func TestHandlerOrderOptionsAndUnsupportedConfiguration(t *testing.T) {
	t.Parallel()

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

	t.Run("unsupported", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0))
		err := runEngineSpecError(t, "x64", `x64:
  push $INPUT
  make pic +unwind
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		if !strings.Contains(err.Error(), "unsupported configured feature(s): +unwind") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("deferred command", func(t *testing.T) {
		t.Parallel()
		object := textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0))
		err := runEngineSpecError(t, "x64", `x64:
  push $INPUT
  make pic
  protect "go"
  export
`, spec.Environment{"$INPUT": marshalTestObject(t, object)}, New())
		if !strings.Contains(err.Error(), "unsupported configured feature(s): protect") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestHandlerRulesAreRequestedOnlyByRuleCommand(t *testing.T) {
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

	t.Run("rule requested", func(t *testing.T) {
		handler := New()
		object := marshalTestObject(t, textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)))
		program, err := spec.Parse("rules.spec", "x64:\n  push $INPUT\n  make pic\n  rule \"sample\"\n  export\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = program.RunAndGenerate(capability, spec.RunOptions{Environment: spec.Environment{"$INPUT": object}, Handler: handler})
		if err == nil || !strings.Contains(err.Error(), "YARA rule generation") {
			t.Fatalf("error = %v, want YARA unsupported error", err)
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

func TestArtifactConfigurationIsDefensiveAndDeterministic(t *testing.T) {
	t.Parallel()
	artifact := newArtifact(KindObject, textObject(t, coff.MachineAMD64, []byte{0xc3}, function("go", 0)))
	artifact.addOptions([]string{"+optimize", "+gofirst", "+optimize"})
	artifact.addStrip([]string{"z", "a", "z"})
	artifact.setPatch("go", []byte{1})
	artifact.setLink(linker.LinkedSection{Name: "blob", Data: []byte{2}})
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
	configuration.Deferred[0].Arguments[0] = "changed"
	again := artifact.Configuration()
	if again.Patches[0].Data[0] != 1 || again.Links[0].Data[0] != 2 || again.Deferred[0].Arguments[0] != "go" {
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

func writeZIP(t *testing.T, path, name string, data []byte) {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	entry, err := archive.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(data); err != nil {
		t.Fatal(err)
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
