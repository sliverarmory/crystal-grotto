// SPDX-License-Identifier: GPL-3.0-only

package ised

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestBuildPlanMatchesFormMnemonicAndAssembly(t *testing.T) {
	t.Parallel()
	program := Program{Machine: coff.MachineAMD64, Functions: []Function{{
		Name: "go", Section: ".text", Instructions: []Instruction{
			instruction(0, []byte{0x53}, "PUSH r64", "push rbx"),
			instruction(1, []byte{0x48, 0x89, 0xd8}, "MOV r64, r64", "mov rax, rbx"),
			instruction(4, []byte{0xc3}, "RET", "ret"),
		},
	}}}
	configuration := mustReplay(t,
		Directive{Arguments: []string{"replace", "PUSH r64", "$FORM"}, Content: []byte{0xa1}},
		Directive{Arguments: []string{"insert", "MOV", "$MNEMONIC"}, Options: []string{"+before"}, Content: []byte{0xb2}},
		Directive{Arguments: []string{"insert", "mov rax, rbx", "$ASSEMBLY"}, Content: []byte{0xc3}},
	)

	plan, err := BuildPlan(program, configuration, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Edits) != 2 {
		t.Fatalf("edits = %#v", plan.Edits)
	}
	if plan.Edits[0].InstructionIndex != 0 || plan.Edits[0].Replace == nil || plan.Edits[0].Replace.CommandIndex != 0 {
		t.Fatalf("form edit = %#v", plan.Edits[0])
	}
	if edit := plan.Edits[1]; edit.InstructionIndex != 1 || edit.Prepend == nil || edit.Prepend.CommandIndex != 1 || edit.Append == nil || edit.Append.CommandIndex != 2 {
		t.Fatalf("mnemonic/assembly edit = %#v", edit)
	}
	plan.Edits[0].Original.Bytes[0] = 0
	plan.Edits[0].Replace.Content[0] = 0
	if program.Functions[0].Instructions[0].Bytes[0] != 0x53 || configuration.Commands()[0].Content[0] != 0xa1 {
		t.Fatal("plan aliases program or configuration")
	}
}

func TestBuildPlanSequenceFirstLastAndFunctionBoundary(t *testing.T) {
	t.Parallel()
	sequence := []Instruction{
		instruction(0, []byte{0x53}, "PUSH r64", "push rbx"),
		instruction(1, []byte{0x48, 0x89, 0xd8}, "MOV r64, r64", "mov rax, rbx"),
	}
	program := Program{Machine: coff.MachineAMD64, Functions: []Function{
		{Name: "first", Section: ".text", Instructions: sequence},
		{Name: "second", Section: ".other", Instructions: []Instruction{
			instruction(0, []byte{0x53}, "PUSH r64", "push rbx"),
		}},
		{Name: "third", Section: ".third", Instructions: []Instruction{
			instruction(0, []byte{0x48, 0x89, 0xd8}, "MOV r64, r64", "mov rax, rbx"),
		}},
	}}
	configuration := mustReplay(t,
		Directive{Arguments: []string{"insert", "PUSH r64", "MOV r64, r64", "$FIRST"}, Options: []string{"+first", "+before"}, Content: []byte{0xa1}},
		Directive{Arguments: []string{"insert", "PUSH r64", "MOV r64, r64", "$LAST"}, Content: []byte{0xb2}},
	)

	plan, err := BuildPlan(program, configuration, PlanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Edits) != 2 || plan.Edits[0].Function != "first" || plan.Edits[0].InstructionIndex != 0 || plan.Edits[0].Prepend == nil || plan.Edits[1].InstructionIndex != 1 || plan.Edits[1].Append == nil {
		t.Fatalf("sequence plan = %#v", plan.Edits)
	}
}

func TestBuildPlanSafetyRelocationAndPointerFix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		instruction Instruction
		options     PlanOptions
		directives  []Directive
		wantBefore  bool
		wantReplace bool
		wantAfter   bool
	}{
		{
			name: "producer phase rules", instruction: withFlags(instruction(0, []byte{0x01, 0xd8}, "ADD r32, r32", "add eax, ebx"), false, true, false),
			directives: []Directive{
				{Arguments: []string{"insert", "ADD", "$BEFORE"}, Options: []string{"+before"}, Content: []byte{1}},
				{Arguments: []string{"replace", "ADD", "$REPLACE"}, Content: []byte{2}},
				{Arguments: []string{"insert", "ADD", "$AFTER"}, Content: []byte{3}},
			}, wantBefore: true,
		},
		{
			name: "consumer phase rules", instruction: withFlags(instruction(0, []byte{0x74, 0}, "JE rel8", "je 2"), false, false, true),
			directives: []Directive{
				{Arguments: []string{"insert", "JE", "$BEFORE"}, Options: []string{"+before"}, Content: []byte{1}},
				{Arguments: []string{"replace", "JE", "$REPLACE"}, Content: []byte{2}},
				{Arguments: []string{"insert", "JE", "$AFTER"}, Content: []byte{3}},
			}, wantAfter: true,
		},
		{
			name: "danger zone safe override", instruction: withFlags(instruction(0, []byte{0x90}, "NOP", "nop"), true, false, false),
			directives: []Directive{
				{Arguments: []string{"replace", "NOP", "$UNSAFE"}, Content: []byte{1}},
				{Arguments: []string{"replace", "NOP", "$SAFE"}, Options: []string{"+safe"}, Content: []byte{2}},
			}, wantReplace: true,
		},
		{
			name: "relocation suppresses replace", instruction: func() Instruction {
				value := instruction(0, []byte{0xff, 0x15, 0, 0, 0, 0}, "CALL r/m64", "call qword ptr [rip]")
				value.HasRelocation = true
				return value
			}(),
			directives: []Directive{
				{Arguments: []string{"replace", "CALL r/m64", "$REPLACE"}, Content: []byte{1}},
				{Arguments: []string{"insert", "CALL r/m64", "$AFTER"}, Content: []byte{2}},
			}, wantAfter: true,
		},
		{
			name: "pointer fix suppresses inserts", instruction: func() Instruction {
				value := instruction(0, []byte{0xe8, 0, 0, 0, 0}, "CALL rel32", "call 5")
				value.PointerFix = true
				return value
			}(),
			directives: []Directive{
				{Arguments: []string{"insert", "CALL rel32", "$BEFORE"}, Options: []string{"+before"}, Content: []byte{1}},
				{Arguments: []string{"replace", "CALL rel32", "$REPLACE"}, Content: []byte{2}},
				{Arguments: []string{"insert", "CALL rel32", "$AFTER"}, Content: []byte{3}},
			}, wantReplace: true,
		},
		{
			name: "unwind bookend", instruction: func() Instruction {
				value := instruction(0, []byte{0x53}, "PUSH r64", "push rbx")
				value.Bookend = true
				return value
			}(),
			options: PlanOptions{Unwind: true}, directives: []Directive{
				{Arguments: []string{"replace", "PUSH", "$SAFE"}, Options: []string{"+safe"}, Content: []byte{1}},
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			configuration := mustReplay(t, test.directives...)
			program := oneInstructionProgram(coff.MachineAMD64, test.instruction)
			plan, err := BuildPlan(program, configuration, test.options)
			if err != nil {
				t.Fatal(err)
			}
			if !test.wantBefore && !test.wantReplace && !test.wantAfter {
				if len(plan.Edits) != 0 {
					t.Fatalf("edits = %#v, want none", plan.Edits)
				}
				return
			}
			if len(plan.Edits) != 1 {
				t.Fatalf("edits = %#v", plan.Edits)
			}
			edit := plan.Edits[0]
			if (edit.Prepend != nil) != test.wantBefore || (edit.Replace != nil) != test.wantReplace || (edit.Append != nil) != test.wantAfter {
				t.Fatalf("edit = %#v", edit)
			}
			if test.name == "danger zone safe override" && edit.Replace.CommandIndex != 1 {
				t.Fatalf("unsafe command selected: %#v", edit.Replace)
			}
		})
	}
}

func TestBuildPlanInjectableRandomnessAndFailure(t *testing.T) {
	t.Parallel()
	configuration := mustReplay(t,
		Directive{Arguments: []string{"replace", "PUSH r64", "$ONE"}, Content: []byte{1}},
		Directive{Arguments: []string{"replace", "PUSH r64", "$TWO"}, Content: []byte{2}},
	)
	program := oneInstructionProgram(coff.MachineAMD64, instruction(0, []byte{0x53}, "PUSH r64", "push rbx"))
	plan, err := BuildPlan(program, configuration, PlanOptions{Random: bytes.NewReader(make([]byte, 8))})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Edits) != 1 || plan.Edits[0].Replace.CommandIndex != 1 || !bytes.Equal(plan.Edits[0].Replace.Content, []byte{2}) {
		t.Fatalf("deterministic selection = %#v", plan.Edits)
	}
	failed, err := BuildPlan(program, configuration, PlanOptions{Random: bytes.NewReader(nil)})
	var randomError *RandomError
	if err == nil || len(failed.Edits) != 0 || !errors.As(err, &randomError) || !errors.Is(err, io.EOF) {
		t.Fatalf("random failure = %#v, %T %v", failed, err, err)
	}
}

func TestBuildPlanTypedSemanticBoundaries(t *testing.T) {
	t.Parallel()
	configuration := mustReplay(t, Directive{Arguments: []string{"replace", "MOV", "$X"}, Content: []byte{0x90}})
	tests := []struct {
		name    string
		program Program
		is      error
	}{
		{name: "machine", program: oneInstructionProgram(coff.MachineARM64, instruction(0, []byte{0x90}, "MOV", "mov")), is: ErrUnsupportedMachine},
		{name: "missing form", program: oneInstructionProgram(coff.MachineAMD64, instruction(0, []byte{0x90}, "", "nop")), is: ErrSemanticDetailUnavailable},
		{name: "missing assembly", program: oneInstructionProgram(coff.MachineAMD64, instruction(0, []byte{0x90}, "NOP", "")), is: ErrSemanticDetailUnavailable},
		{name: "long instruction", program: oneInstructionProgram(coff.MachineAMD64, instruction(0, make([]byte, 16), "NOP", "nop")), is: ErrInvalidProgram},
		{name: "duplicate function", program: Program{Machine: coff.MachineAMD64, Functions: []Function{{Name: "go", Section: ".text"}, {Name: "go", Section: ".text"}}}, is: ErrInvalidProgram},
		{name: "instruction order", program: Program{Machine: coff.MachineAMD64, Functions: []Function{{Name: "go", Section: ".text", Instructions: []Instruction{
			instruction(1, []byte{0x90}, "NOP", "nop"), instruction(0, []byte{0x90}, "NOP", "nop"),
		}}}}, is: ErrInvalidProgram},
		{name: "overlap", program: Program{Machine: coff.MachineAMD64, Functions: []Function{
			{Name: "one", Section: ".text", Instructions: []Instruction{instruction(0, []byte{0x90, 0x90}, "NOP", "nop")}},
			{Name: "two", Section: ".text", Instructions: []Instruction{instruction(1, []byte{0x90}, "NOP", "nop")}},
		}}, is: ErrInvalidProgram},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := BuildPlan(test.program, configuration, PlanOptions{})
			if !errors.Is(err, test.is) {
				t.Fatalf("error = %T %v, want %v", err, err, test.is)
			}
			if test.is == ErrSemanticDetailUnavailable {
				var boundary *BoundaryError
				if !errors.As(err, &boundary) {
					t.Fatalf("boundary error type = %T", err)
				}
			}
		})
	}

	empty, err := BuildPlan(Program{Machine: coff.MachineAMD64}, EmptyConfiguration(), PlanOptions{})
	if err != nil || empty.Edits == nil || len(empty.Edits) != 0 {
		t.Fatalf("empty configuration plan = %#v, %v", empty, err)
	}
}

func TestConfigurationAndPlanningAreConcurrentReadSafe(t *testing.T) {
	t.Parallel()
	configuration := mustReplay(t, Directive{Arguments: []string{"replace", "MOV r64, r64", "$X"}, Content: []byte{0xcc, 0xcc, 0xcc}})
	program := oneInstructionProgram(coff.MachineAMD64, instruction(0, []byte{0x48, 0x89, 0xd8}, "MOV r64, r64", "mov rax, rbx"))
	const workers = 32
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			plan, err := BuildPlan(program, configuration, PlanOptions{})
			if err != nil {
				errorsChannel <- err
				return
			}
			if len(plan.Edits) != 1 || !reflect.DeepEqual(plan.Edits[0].Replace.Content, []byte{0xcc, 0xcc, 0xcc}) {
				errorsChannel <- errors.New("unexpected concurrent plan")
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func FuzzBuildPlan(f *testing.F) {
	f.Add("MOV r64, r64", []byte{0xcc}, false, false, false)
	f.Add("MOV", []byte{0x90, 0x90}, true, true, true)
	f.Fuzz(func(t *testing.T, pattern string, content []byte, before, first, safe bool) {
		if len(pattern) > 128 {
			pattern = pattern[:128]
		}
		if len(content) > 256 {
			content = content[:256]
		}
		options := []string{}
		if before {
			options = append(options, "+before")
		}
		if first {
			options = append(options, "+first")
		}
		if safe {
			options = append(options, "+safe")
		}
		configuration := mustReplay(t, Directive{Arguments: []string{"insert", pattern, "$X"}, Options: options, Content: content})
		program := oneInstructionProgram(coff.MachineAMD64, instruction(0, []byte{0x48, 0x89, 0xd8}, "MOV r64, r64", "mov rax, rbx"))
		original := append([]byte(nil), program.Functions[0].Instructions[0].Bytes...)
		_, err := BuildPlan(program, configuration, PlanOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(program.Functions[0].Instructions[0].Bytes, original) {
			t.Fatal("BuildPlan mutated program")
		}
	})
}

func instruction(offset uint32, raw []byte, form, assembly string) Instruction {
	return Instruction{Offset: offset, Bytes: append([]byte(nil), raw...), Form: form, Assembly: assembly}
}

func oneInstructionProgram(machine coff.Machine, value Instruction) Program {
	return Program{Machine: machine, Functions: []Function{{Name: "go", Section: ".text", Instructions: []Instruction{value}}}}
}

func withFlags(value Instruction, danger, producer, consumer bool) Instruction {
	value.DangerZone, value.FlagProducer, value.FlagConsumer = danger, producer, consumer
	return value
}

func mustReplay(t *testing.T, directives ...Directive) Configuration {
	t.Helper()
	configuration, err := Replay(EmptyConfiguration(), directives)
	if err != nil {
		t.Fatal(err)
	}
	return configuration
}
