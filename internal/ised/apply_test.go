// SPDX-License-Identifier: GPL-3.0-only

package ised

import (
	"bytes"
	"errors"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestApplyFixedBackendExactX86AndX64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		machine  coff.Machine
		code     []byte
		original Instruction
		content  []byte
		want     []byte
	}{
		{
			name: "x64 push", machine: coff.MachineAMD64, code: []byte{0x53, 0xc3},
			original: instruction(0, []byte{0x53}, "PUSH r64", "push rbx"), content: []byte{0xcc}, want: []byte{0xcc, 0xc3},
		},
		{
			name: "x86 mov", machine: coff.MachineI386, code: []byte{0x89, 0xd8, 0xc3},
			original: instruction(0, []byte{0x89, 0xd8}, "MOV r32, r32", "mov eax, ebx"), content: []byte{0x31, 0xc0}, want: []byte{0x31, 0xc0, 0xc3},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			object := testObject(t, test.machine, test.code)
			program := oneInstructionProgram(test.machine, test.original)
			configuration := mustReplay(t, Directive{Arguments: []string{"replace", test.original.Form, "$CODE"}, Content: test.content})

			result, plan, err := Apply(object, program, configuration, PlanOptions{}, FixedBackend{})
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Edits) != 1 || !bytes.Equal(result.GetSection(".text").Data, test.want) {
				t.Fatalf("result/plan = %x / %#v", result.GetSection(".text").Data, plan)
			}
			if !bytes.Equal(object.GetSection(".text").Data, test.code) {
				t.Fatal("Apply mutated input")
			}
		})
	}
}

func TestApplyFixedBackendExactSplitVectors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		options []string
		want    []byte
	}{
		{name: "suffix", options: []string{"+split"}, want: []byte{0x90, 0xeb, 0}},
		{name: "prefix first", options: []string{"+split", "+first"}, want: []byte{0xeb, 0, 0x90}},
		{name: "prefix before", options: []string{"+split", "+before"}, want: []byte{0xeb, 0, 0x90}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			code := []byte{0x83, 0xc0, 0x01}
			object := testObject(t, coff.MachineI386, code)
			original := instruction(0, code, "ADD r32, imm8", "add eax, 1")
			program := oneInstructionProgram(coff.MachineI386, original)
			configuration := mustReplay(t, Directive{
				Arguments: []string{"replace", original.Form, "$CODE"}, Options: test.options, Content: []byte{0x90},
			})
			result, _, err := Apply(object, program, configuration, PlanOptions{}, FixedBackend{})
			if err != nil {
				t.Fatal(err)
			}
			if got := result.GetSection(".text").Data; !bytes.Equal(got, test.want) {
				t.Fatalf("split bytes = %x, want %x", got, test.want)
			}
		})
	}
}

func TestApplyReportsReencoderBoundaryTransactionally(t *testing.T) {
	t.Parallel()
	object := testObject(t, coff.MachineAMD64, []byte{0x53, 0xc3})
	program := oneInstructionProgram(coff.MachineAMD64, instruction(0, []byte{0x53}, "PUSH r64", "push rbx"))
	configuration := mustReplay(t, Directive{Arguments: []string{"insert", "PUSH r64", "$CODE"}, Content: []byte{0xcc}})

	if result, plan, err := Apply(object, program, configuration, PlanOptions{}, nil); result != nil || len(plan.Edits) != 1 || !errors.Is(err, ErrReencoderUnavailable) {
		t.Fatalf("nil backend = %#v, %#v, %v", result, plan, err)
	}
	result, plan, err := Apply(object, program, configuration, PlanOptions{}, FixedBackend{})
	var boundary *BoundaryError
	if result != nil || len(plan.Edits) != 1 || !errors.Is(err, ErrReencoderUnavailable) || !errors.As(err, &boundary) {
		t.Fatalf("fixed backend = %#v, %#v, %T %v", result, plan, err, err)
	}
	if !bytes.Equal(object.GetSection(".text").Data, []byte{0x53, 0xc3}) {
		t.Fatal("failed rewrite mutated input")
	}
}

func TestApplyCustomBackendIsTransactional(t *testing.T) {
	t.Parallel()
	newFixture := func(t *testing.T) (*coff.Object, Program, Configuration) {
		t.Helper()
		object := testObject(t, coff.MachineAMD64, []byte{0x53, 0xc3})
		program := oneInstructionProgram(coff.MachineAMD64, instruction(0, []byte{0x53}, "PUSH r64", "push rbx"))
		configuration := mustReplay(t, Directive{Arguments: []string{"replace", "PUSH r64", "$CODE"}, Content: []byte{0xcc}})
		return object, program, configuration
	}

	t.Run("backend error", func(t *testing.T) {
		object, program, configuration := newFixture(t)
		backendError := errors.New("encoder failed")
		result, _, err := Apply(object, program, configuration, PlanOptions{}, RewriteBackendFunc(func(candidate *coff.Object, received Program, plan Plan) error {
			candidate.GetSection(".text").Data[0] = 0
			received.Functions[0].Instructions[0].Bytes[0] = 0
			plan.Edits[0].Replace.Content[0] = 0
			return backendError
		}))
		if result != nil || !errors.Is(err, backendError) {
			t.Fatalf("result/error = %#v, %v", result, err)
		}
		if object.GetSection(".text").Data[0] != 0x53 || program.Functions[0].Instructions[0].Bytes[0] != 0x53 || configuration.Commands()[0].Content[0] != 0xcc {
			t.Fatal("backend mutation escaped transaction/defensive copies")
		}
	})

	t.Run("success", func(t *testing.T) {
		object, program, configuration := newFixture(t)
		result, _, err := Apply(object, program, configuration, PlanOptions{}, RewriteBackendFunc(func(candidate *coff.Object, _ Program, _ Plan) error {
			candidate.GetSection(".text").Data = []byte{0x90, 0x90, 0xc3}
			candidate.GetSection(".text").SizeOfRawData = 3
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		if got := result.GetSection(".text").Data; !bytes.Equal(got, []byte{0x90, 0x90, 0xc3}) {
			t.Fatalf("backend bytes = %x", got)
		}
		if got := object.GetSection(".text").Data; !bytes.Equal(got, []byte{0x53, 0xc3}) {
			t.Fatalf("input bytes = %x", got)
		}
	})
}

func TestApplyValidatesSemanticObjectIdentity(t *testing.T) {
	t.Parallel()
	configuration := mustReplay(t, Directive{Arguments: []string{"replace", "PUSH r64", "$CODE"}, Content: []byte{0xcc}})
	tests := []struct {
		name    string
		object  func(*testing.T) *coff.Object
		program Program
	}{
		{
			name: "machine", object: func(t *testing.T) *coff.Object { return testObject(t, coff.MachineI386, []byte{0x53}) },
			program: oneInstructionProgram(coff.MachineAMD64, instruction(0, []byte{0x53}, "PUSH r64", "push rbx")),
		},
		{
			name: "bytes", object: func(t *testing.T) *coff.Object { return testObject(t, coff.MachineAMD64, []byte{0x90}) },
			program: oneInstructionProgram(coff.MachineAMD64, instruction(0, []byte{0x53}, "PUSH r64", "push rbx")),
		},
		{
			name: "missing section", object: func(t *testing.T) *coff.Object { return testObject(t, coff.MachineAMD64, []byte{0x53}) },
			program: Program{Machine: coff.MachineAMD64, Functions: []Function{{Name: "go", Section: ".missing", Instructions: []Instruction{instruction(0, []byte{0x53}, "PUSH r64", "push rbx")}}}},
		},
		{
			name: "stale relocation", object: func(t *testing.T) *coff.Object {
				object := testObject(t, coff.MachineAMD64, []byte{0x53, 0, 0, 0, 0})
				text := object.GetSection(".text")
				target := &coff.Symbol{Name: "target", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
				if err := object.AddSymbol(target); err != nil {
					t.Fatal(err)
				}
				text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 0, SymbolName: target.Name, Symbol: target, Type: coff.RelAMD64Rel32}}
				return object
			},
			program: oneInstructionProgram(coff.MachineAMD64, instruction(0, []byte{0x53}, "PUSH r64", "push rbx")),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, _, err := Apply(test.object(t), test.program, configuration, PlanOptions{}, FixedBackend{})
			if result != nil || !errors.Is(err, ErrInvalidProgram) {
				t.Fatalf("result/error = %#v, %T %v", result, err, err)
			}
		})
	}
}

func TestApplyNoEditsReturnsIndependentClone(t *testing.T) {
	t.Parallel()
	object := testObject(t, coff.MachineAMD64, []byte{0xc3})
	result, plan, err := Apply(object, Program{Machine: coff.MachineAMD64}, EmptyConfiguration(), PlanOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result == object || plan.Edits == nil || len(plan.Edits) != 0 {
		t.Fatalf("result/plan = %#v / %#v", result, plan)
	}
	result.GetSection(".text").Data[0] = 0x90
	if object.GetSection(".text").Data[0] != 0xc3 {
		t.Fatal("clone aliases input")
	}
}

func FuzzApplyFixedReplacement(f *testing.F) {
	f.Add(byte(0x90), byte(0x90))
	f.Add(byte(0x31), byte(0xc0))
	f.Fuzz(func(t *testing.T, first, second byte) {
		code := []byte{0x89, 0xd8, 0xc3}
		object := testObject(t, coff.MachineI386, code)
		original := instruction(0, code[:2], "MOV r32, r32", "mov eax, ebx")
		program := oneInstructionProgram(coff.MachineI386, original)
		configuration := mustReplay(t, Directive{Arguments: []string{"replace", original.Form, "$X"}, Content: []byte{first, second}})
		result, _, err := Apply(object, program, configuration, PlanOptions{}, FixedBackend{})
		if err != nil {
			t.Fatal(err)
		}
		if got := result.GetSection(".text").Data; !bytes.Equal(got, []byte{first, second, 0xc3}) {
			t.Fatalf("result = %x", got)
		}
	})
}

func testObject(t *testing.T, machine coff.Machine, code []byte) *coff.Object {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	if err := object.AddSection(coff.NewSection(".text", code)); err != nil {
		t.Fatal(err)
	}
	return object
}
