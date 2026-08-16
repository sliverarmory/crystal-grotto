// SPDX-License-Identifier: GPL-3.0-only

package ised

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestLiftObjectProvesRawFormsFlagsAndBookends(t *testing.T) {
	t.Parallel()
	code := []byte{
		0x53,                   // push rbx
		0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0x48, 0x31, 0xc0, // xor rax, rax
		0x74, 0x01, // je ret
		0x90, // nop
		0xc3, // ret
	}
	object := isedObjectWithFunction(t, coff.MachineAMD64, code, "go", 0)
	program, err := LiftObject(context.Background(), object, ObjectOptions{Unwind: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(program.Functions) != 1 || len(program.Functions[0].Instructions) != 7 {
		t.Fatalf("program = %#v", program)
	}
	instructions := program.Functions[0].Instructions
	wantForms := []string{"PUSH r64", "SUB r/m64, imm8", "MOV r/m64, r64", "XOR r/m64, r64", "JE rel8", "NOP", "RET"}
	for index, want := range wantForms {
		if instructions[index].Form != want {
			t.Fatalf("instruction %d form = %q, want %q", index, instructions[index].Form, want)
		}
	}
	if instructions[0].Assembly != "push rbx" || instructions[2].Assembly != "mov rbp, rsp" || instructions[3].Assembly != "xor rax, rax" {
		t.Fatalf("exact assembly = %q / %q / %q", instructions[0].Assembly, instructions[2].Assembly, instructions[3].Assembly)
	}
	if !instructions[0].Bookend || !instructions[1].Bookend || !instructions[2].Bookend || !instructions[6].Bookend {
		t.Fatalf("bookends = %#v", instructions)
	}
	if !instructions[3].FlagProducer || !instructions[4].FlagConsumer || instructions[5].DangerZone {
		t.Fatalf("flag analysis = %#v", instructions)
	}
	if !instructions[4].PCRelative || instructions[4].RelativeTarget != 14 || instructions[4].RelativeWidth != 1 {
		t.Fatalf("relative JE = %#v", instructions[4])
	}
}

func TestApplyObjectRebasesBranchesAndPrependTargets(t *testing.T) {
	t.Parallel()
	t.Run("ordinary branch label follows prepend", func(t *testing.T) {
		object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0xeb, 0x00, 0x90, 0xc3}, "go", 0)
		configuration := mustReplay(t, Directive{Arguments: []string{"insert", "NOP", "$X"}, Options: []string{"+before"}, Content: []byte{0xcc}})
		result, _, plan, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{0xeb, 0x01, 0xcc, 0x90, 0xc3}
		if got := result.GetSection(".text").Data; !bytes.Equal(got, want) || len(plan.Edits) != 1 {
			t.Fatalf("result/plan = %x / %#v, want %x", got, plan, want)
		}
	})

	t.Run("named function label precedes prepend", func(t *testing.T) {
		object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0xeb, 0x00, 0x90, 0xc3}, "go", 0)
		addISEDTestFunction(t, object, "target", 2)
		configuration := mustReplay(t, Directive{Arguments: []string{"insert", "NOP", "$X"}, Options: []string{"+before"}, Content: []byte{0xcc}})
		result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{0xeb, 0x00, 0xcc, 0x90, 0xc3}
		if got := result.GetSection(".text").Data; !bytes.Equal(got, want) {
			t.Fatalf("result = %x, want %x", got, want)
		}
		if result.GetSymbol("target").Value != 2 {
			t.Fatalf("target symbol = %#x, want %#x", result.GetSymbol("target").Value, 2)
		}
	})

	t.Run("multiple inserts repair near branch", func(t *testing.T) {
		object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0xe9, 0x02, 0, 0, 0, 0x90, 0x90, 0xc3}, "go", 0)
		configuration := mustReplay(t, Directive{Arguments: []string{"insert", "NOP", "$X"}, Content: []byte{0xcc}})
		result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{0xe9, 0x04, 0, 0, 0, 0x90, 0xcc, 0x90, 0xcc, 0xc3}
		if got := result.GetSection(".text").Data; !bytes.Equal(got, want) {
			t.Fatalf("result = %x, want %x", got, want)
		}
	})
}

func TestApplyObjectRebasesSymbolsRelocationsAndSectionAddends(t *testing.T) {
	t.Parallel()
	object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0x90, 0xe8, 0, 0, 0, 0, 0xc3}, "go", 0)
	addISEDTestFunction(t, object, "tail", 6)
	object.GetSymbol("go").AuxiliaryRecords = [][]byte{make([]byte, 18)}
	binary.LittleEndian.PutUint32(object.GetSymbol("go").AuxiliaryRecords[0][4:8], 6)
	text := object.GetSection(".text")
	external := &coff.Symbol{Name: "external", StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(external); err != nil {
		t.Fatal(err)
	}
	text.Relocations = append(text.Relocations, &coff.Relocation{
		Section: text, VirtualAddress: 2, SymbolName: external.Name, Symbol: external, Type: coff.RelAMD64Rel32,
	})
	rdata := coff.NewSection(".rdata", make([]byte, 4))
	binary.LittleEndian.PutUint32(rdata.Data, 6)
	if err := object.AddSection(rdata); err != nil {
		t.Fatal(err)
	}
	textSectionSymbol := object.GetSymbol(".text")
	rdata.Relocations = append(rdata.Relocations, &coff.Relocation{
		Section: rdata, VirtualAddress: 0, SymbolName: textSectionSymbol.Name, Symbol: textSectionSymbol, Type: coff.RelAMD64Addr32NB,
	})
	configuration := mustReplay(t, Directive{Arguments: []string{"insert", "NOP", "$X"}, Content: []byte{0xcc}})

	result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.GetSection(".text").Data; !bytes.Equal(got, []byte{0x90, 0xcc, 0xe8, 0, 0, 0, 0, 0xc3}) {
		t.Fatalf("text = %x", got)
	}
	if relocation := result.GetSection(".text").Relocations[0]; relocation.VirtualAddress != 3 || relocation.SymbolName != "external" {
		t.Fatalf("text relocation = %#v", relocation)
	}
	if got := result.GetSymbol("tail").Value; got != 7 {
		t.Fatalf("tail = %#x, want 7", got)
	}
	if got := binary.LittleEndian.Uint32(result.GetSymbol("go").AuxiliaryRecords[0][4:8]); got != 7 {
		t.Fatalf("function auxiliary size = %#x, want 7", got)
	}
	if got := binary.LittleEndian.Uint32(result.GetSection(".rdata").Data); got != 7 {
		t.Fatalf("section addend = %#x, want 7", got)
	}
	if object.GetSymbol("tail").Value != 6 || object.GetSection(".text").Relocations[0].VirtualAddress != 2 || binary.LittleEndian.Uint32(object.GetSection(".rdata").Data) != 6 {
		t.Fatal("ApplyObject mutated its input")
	}
}

func TestApplyObjectX86RawFormVector(t *testing.T) {
	t.Parallel()
	object := isedObjectWithFunction(t, coff.MachineI386, []byte{0x53, 0x89, 0xd8, 0xc3}, "_go", 0)
	configuration := mustReplay(t, Directive{
		Arguments: []string{"replace", "MOV r/m32, r32", "$X"}, Content: []byte{0x31, 0xc0},
	})
	result, program, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := result.GetSection(".text").Data; !bytes.Equal(got, []byte{0x53, 0x31, 0xc0, 0xc3}) {
		t.Fatalf("x86 result = %x", got)
	}
	if form := program.Functions[0].Instructions[1].Form; form != "MOV r/m32, r32" {
		t.Fatalf("x86 form = %q", form)
	}
}

func TestApplyObjectRepairsProvenRIPRelativeReference(t *testing.T) {
	t.Parallel()
	code := []byte{0x90, 0x48, 0x8b, 0x05, 0x01, 0, 0, 0, 0xc3, 0x90}
	object := isedObjectWithFunction(t, coff.MachineAMD64, code, "go", 0)
	if err := object.AddSymbol(coff.NewDataSymbol(object.GetSection(".text"), "data", 9)); err != nil {
		t.Fatal(err)
	}
	configuration := mustReplay(t, Directive{Arguments: []string{"insert", "MOV r64, r/m64", "$X"}, Content: []byte{0xcc}})
	result, program, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x90, 0x48, 0x8b, 0x05, 0x02, 0, 0, 0, 0xcc, 0xc3, 0x90}
	if got := result.GetSection(".text").Data; !bytes.Equal(got, want) {
		t.Fatalf("RIP-relative result = %x, want %x", got, want)
	}
	if result.GetSymbol("data").Value != 10 {
		t.Fatalf("data symbol = %#x, want 10", result.GetSymbol("data").Value)
	}
	if instruction := program.Functions[0].Instructions[1]; !instruction.PCRelative || !instruction.RelativeTargetBefore || instruction.RelativeTarget != 9 {
		t.Fatalf("RIP-relative semantics = %#v", instruction)
	}
}

func TestLiftObjectPointerFixParity(t *testing.T) {
	t.Parallel()
	object := isedObjectWithFunction(t, coff.MachineI386, []byte{0xe8, 0x01, 0, 0, 0, 0xc3, 0xc3}, "_go", 0)
	addISEDTestFunction(t, object, "_retaddr", 6)
	configuration := mustReplay(t,
		Directive{Arguments: []string{"insert", "CALL rel32", "$BEFORE"}, Options: []string{"+before"}, Content: []byte{0xcc}},
		Directive{Arguments: []string{"insert", "CALL rel32", "$AFTER"}, Content: []byte{0xcc}},
	)
	result, program, plan, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{ReturnAddress: "_retaddr"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Edits) != 0 || !program.Functions[0].Instructions[0].PointerFix {
		t.Fatalf("program/plan = %#v / %#v", program, plan)
	}
	if got := result.GetSection(".text").Data; !bytes.Equal(got, []byte{0xe8, 0x01, 0, 0, 0, 0xc3, 0xc3}) {
		t.Fatalf("pointer-fix result = %x", got)
	}
}

func TestApplyObjectSplitAndReplacementVector(t *testing.T) {
	t.Parallel()
	object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0x48, 0x89, 0xd8, 0xc3}, "go", 0)
	configuration := mustReplay(t, Directive{
		Arguments: []string{"replace", "MOV r/m64, r64", "$X"}, Options: []string{"+split"}, Content: []byte{0xcc, 0x90},
	})
	result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xcc, 0x90, 0xeb, 0x00, 0xc3}
	if got := result.GetSection(".text").Data; !bytes.Equal(got, want) {
		t.Fatalf("result = %x, want %x", got, want)
	}
}

func TestApplyObjectSemanticBoundariesFailClosed(t *testing.T) {
	t.Parallel()
	t.Run("specific assembly needs Iced detail", func(t *testing.T) {
		object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0x0f, 0xaf, 0xc1, 0xc3}, "go", 0)
		configuration := mustReplay(t, Directive{Arguments: []string{"replace", "imul eax, ecx", "$X"}, Content: []byte{0x90}})
		result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
		var boundary *BoundaryError
		if result != nil || !errors.Is(err, ErrSemanticDetailUnavailable) || !errors.As(err, &boundary) {
			t.Fatalf("result/error = %#v, %T %v", result, err, err)
		}
	})

	t.Run("unrelated incomplete instruction is harmless", func(t *testing.T) {
		object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0x0f, 0xaf, 0xc1, 0xc3}, "go", 0)
		configuration := mustReplay(t, Directive{Arguments: []string{"replace", "NOP", "$X"}, Content: []byte{0x90}})
		result, _, plan, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
		if err != nil || result == nil || len(plan.Edits) != 0 {
			t.Fatalf("result/plan/error = %#v / %#v / %v", result, plan, err)
		}
	})

	t.Run("unknown RIP form blocks length change", func(t *testing.T) {
		original := []byte{0x90, 0x48, 0x03, 0x05, 0, 0, 0, 0, 0xc3}
		object := isedObjectWithFunction(t, coff.MachineAMD64, original, "go", 0)
		configuration := mustReplay(t, Directive{Arguments: []string{"insert", "NOP", "$X"}, Content: []byte{0xcc}})
		result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
		if result != nil || !errors.Is(err, ErrSemanticDetailUnavailable) {
			t.Fatalf("result/error = %#v, %T %v", result, err, err)
		}
		if !bytes.Equal(object.GetSection(".text").Data, original) {
			t.Fatal("failed rewrite mutated input")
		}
	})

	t.Run("relocation proves unknown RIP field", func(t *testing.T) {
		object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0x90, 0x48, 0x03, 0x05, 0, 0, 0, 0, 0xc3}, "go", 0)
		external := &coff.Symbol{Name: "external_data", StorageClass: coff.SymbolClassExternal}
		if err := object.AddSymbol(external); err != nil {
			t.Fatal(err)
		}
		text := object.GetSection(".text")
		text.Relocations = append(text.Relocations, &coff.Relocation{
			Section: text, VirtualAddress: 4, SymbolName: external.Name, Symbol: external, Type: coff.RelAMD64Rel32,
		})
		configuration := mustReplay(t, Directive{Arguments: []string{"insert", "NOP", "$X"}, Content: []byte{0xcc}})
		result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got := result.GetSection(".text").Relocations[0].VirtualAddress; got != 5 {
			t.Fatalf("RIP relocation = %#x, want 5", got)
		}
	})
}

func TestApplyObjectReportsShortBranchRangeTransactionally(t *testing.T) {
	t.Parallel()
	code := append([]byte{0xeb, 0x7e}, bytes.Repeat([]byte{0x90}, 126)...)
	code = append(code, 0xc3)
	object := isedObjectWithFunction(t, coff.MachineAMD64, code, "go", 0)
	configuration := mustReplay(t, Directive{Arguments: []string{"insert", "NOP", "$X"}, Content: []byte{0xcc}})
	result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
	var rangeError *BranchRangeError
	if result != nil || !errors.Is(err, ErrBranchOutOfRange) || !errors.As(err, &rangeError) {
		t.Fatalf("result/error = %#v, %T %v", result, err, err)
	}
	if !bytes.Equal(object.GetSection(".text").Data, code) {
		t.Fatal("range failure mutated input")
	}
}

func TestApplyObjectUnwindBookendsAndPdata(t *testing.T) {
	t.Parallel()
	newObject := func(t *testing.T) *coff.Object {
		object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0x53, 0x90, 0x5b, 0xc3}, "go", 0)
		pdata := coff.NewSection(".pdata", make([]byte, 12))
		binary.LittleEndian.PutUint32(pdata.Data[4:8], 4)
		if err := object.AddSection(pdata); err != nil {
			t.Fatal(err)
		}
		textSymbol := object.GetSymbol(".text")
		for _, offset := range []uint32{0, 4} {
			pdata.Relocations = append(pdata.Relocations, &coff.Relocation{
				Section: pdata, VirtualAddress: offset, SymbolName: textSymbol.Name, Symbol: textSymbol, Type: coff.RelAMD64Addr32NB,
			})
		}
		return object
	}

	t.Run("bookends reject edits", func(t *testing.T) {
		object := newObject(t)
		configuration := mustReplay(t, Directive{Arguments: []string{"insert", "PUSH", "$X"}, Options: []string{"+safe"}, Content: []byte{0xcc}})
		result, program, plan, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{Unwind: true})
		if err != nil || result == nil || len(plan.Edits) != 0 || !program.Functions[0].Instructions[0].Bookend {
			t.Fatalf("result/program/plan/error = %#v / %#v / %#v / %v", result, program, plan, err)
		}
	})

	t.Run("relocation-backed range is rebased", func(t *testing.T) {
		object := newObject(t)
		configuration := mustReplay(t, Directive{Arguments: []string{"insert", "NOP", "$X"}, Content: []byte{0xcc}})
		result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{Unwind: true})
		if err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint32(result.GetSection(".pdata").Data[4:8]); got != 5 {
			t.Fatalf("pdata end = %d, want 5", got)
		}
	})

	t.Run("existing pdata requires unwind-aware planning", func(t *testing.T) {
		object := newObject(t)
		configuration := mustReplay(t, Directive{Arguments: []string{"insert", "NOP", "$X"}, Content: []byte{0xcc}})
		result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
		if result != nil || !errors.Is(err, ErrUnsupportedUnwind) {
			t.Fatalf("result/error = %#v, %T %v", result, err, err)
		}
	})
}

func TestApplyObjectConcurrentReadSafe(t *testing.T) {
	t.Parallel()
	object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0xeb, 0x01, 0x90, 0xc3}, "go", 0)
	configuration := mustReplay(t, Directive{Arguments: []string{"insert", "NOP", "$X"}, Content: []byte{0xcc}})
	// Each worker owns a portable decoder instance. Four simultaneous callers
	// exercise the shared-object race boundary without forcing smaller CI
	// runners into memory-pressure thrashing under the race detector.
	const workers = 4
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, _, _, err := ApplyObject(context.Background(), object, configuration, ObjectOptions{})
			if err != nil {
				errorsChannel <- err
				return
			}
			if got := result.GetSection(".text").Data; !bytes.Equal(got, []byte{0xeb, 0x02, 0x90, 0xcc, 0xc3}) {
				errorsChannel <- fmt.Errorf("result = %x", got)
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	if !bytes.Equal(object.GetSection(".text").Data, []byte{0xeb, 0x01, 0x90, 0xc3}) {
		t.Fatal("concurrent operations mutated input")
	}
}

func TestApplyObjectInputAndCancellation(t *testing.T) {
	t.Parallel()
	if _, err := LiftObject(nil, nil, ObjectOptions{}); !errors.Is(err, ErrNilContext) {
		t.Fatalf("nil context error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	object := isedObjectWithFunction(t, coff.MachineAMD64, []byte{0xc3}, "go", 0)
	if _, err := LiftObject(cancelled, object, ObjectOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

func FuzzDecodeSemanticRawBoundary(f *testing.F) {
	f.Add([]byte{0x48, 0x89, 0xd8}, "mov", "rax, rbx")
	f.Add([]byte{0x74, 0x00}, "je", "2")
	f.Add([]byte{0x48, 0x03, 0x05, 0, 0, 0, 0}, "add", "rax, qword ptr [rip]")
	f.Fuzz(func(t *testing.T, raw []byte, mnemonic, operands string) {
		if len(raw) == 0 || len(raw) > 15 || len(mnemonic) > 32 || len(operands) > 128 {
			t.Skip()
		}
		instruction := decodeSemantic(coff.MachineAMD64, 0, x86.Instruction{
			Address: 0, Bytes: append([]byte(nil), raw...), Mnemonic: mnemonic, Operands: operands,
		}, uint32(len(raw)), nil)
		if !bytes.Equal(instruction.Bytes, raw) || instruction.Offset != 0 {
			t.Fatalf("decoded instruction lost raw identity: %#v", instruction)
		}
	})
}

func isedObjectWithFunction(t *testing.T, machine coff.Machine, code []byte, name string, offset uint32) *coff.Object {
	t.Helper()
	object := testObject(t, machine, code)
	addISEDTestFunction(t, object, name, offset)
	return object
}

func addISEDTestFunction(t *testing.T, object *coff.Object, name string, offset uint32) {
	t.Helper()
	if err := object.AddSymbol(coff.NewFunctionSymbol(object.GetSection(".text"), name, offset)); err != nil {
		t.Fatal(err)
	}
}
