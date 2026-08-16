// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package transfer

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

func TestApplyExactUpstreamX64Vector(t *testing.T) {
	code := []byte{
		0x53,                   // push rbx
		0x56,                   // push rsi
		0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
		0xe8, 0, 0, 0, 0, // call __transfer
		0x90, // consumed placeholder
		0xc3,
	}
	object, text, function, transferRelocation := testTransferObject(t, coff.MachineAMD64, code, 6)
	function.AuxiliaryRecords = [][]byte{make([]byte, 18)}
	report, err := Apply(context.Background(), object, Options{})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := []byte{
		0x53, 0x56, 0x48, 0x83, 0xec, 0x28,
		0x48, 0x83, 0xc4, 0x28, // add rsp, 0x28
		0x5e, 0x5b, // pop rsi; pop rbx
		0xff, 0xe1, // jmp rcx
		0xc3,
	}
	if !bytes.Equal(text.Data, want) {
		t.Fatalf("text = %x, want %x", text.Data, want)
	}
	if len(text.Relocations) != 0 {
		t.Fatalf("relocations = %#v; consumed relocation %p remains", text.Relocations, transferRelocation)
	}
	if report.RewrittenCalls != 1 || report.ConsumedNOPs != 1 || report.BytesBefore != len(code) || report.BytesAfter != len(want) {
		t.Fatalf("report = %#v", report)
	}
	if len(report.Functions) != 1 || report.Functions[0].Name != "go" || report.Functions[0].Calls != 1 || fmt.Sprint(report.Functions[0].CallOffsets) != "[6]" {
		t.Fatalf("function report = %#v", report.Functions)
	}
	if got, wantEpilogue := report.Functions[0].Epilogue, []byte{0x48, 0x83, 0xc4, 0x28, 0x5e, 0x5b}; !bytes.Equal(got, wantEpilogue) {
		t.Fatalf("epilogue = %x, want %x", got, wantEpilogue)
	}
	clone := report.Clone()
	clone.Functions[0].Epilogue[0] ^= 0xff
	clone.Functions[0].CallOffsets[0]++
	if bytes.Equal(clone.Functions[0].Epilogue, report.Functions[0].Epilogue) || clone.Functions[0].CallOffsets[0] == report.Functions[0].CallOffsets[0] {
		t.Fatal("Report.Clone aliases report slices")
	}
	if got := binary.LittleEndian.Uint32(function.AuxiliaryRecords[0][4:8]); got != uint32(len(want)) {
		t.Fatalf("function auxiliary size = %d, want %d", got, len(want))
	}
}

func TestApplyVolatileExtendedAndImm32PrologueVector(t *testing.T) {
	code := []byte{
		0x51,       // push rcx: discard without clobbering transfer target
		0x41, 0x54, // push r12
		0x48, 0x81, 0xec, 0x80, 0, 0, 0,
		0xe8, 0, 0, 0, 0,
		0x90, 0xc3,
	}
	object, text, _, _ := testTransferObject(t, coff.MachineAMD64, code, 10)
	_, err := Apply(context.Background(), object, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x51, 0x41, 0x54, 0x48, 0x81, 0xec, 0x80, 0, 0, 0,
		0x48, 0x81, 0xc4, 0x80, 0, 0, 0,
		0x41, 0x5c,
		0x48, 0x83, 0xc4, 0x08,
		0xff, 0xe1, 0xc3,
	}
	if !bytes.Equal(text.Data, want) {
		t.Fatalf("text = %x, want %x", text.Data, want)
	}
}

func TestApplyFramePointerStopsPrologueWalk(t *testing.T) {
	code := []byte{
		0x55,
		0x48, 0x83, 0xec, 0x20,
		0x48, 0x8d, 0x6c, 0x24, 0x20, // lea rbp, [rsp+0x20]
		0xe8, 0, 0, 0, 0, 0x90, 0xc3,
	}
	object, text, _, _ := testTransferObject(t, coff.MachineAMD64, code, 10)
	_, err := Apply(context.Background(), object, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x55, 0x48, 0x83, 0xec, 0x20,
		0x48, 0x8d, 0x6c, 0x24, 0x20,
		0x48, 0x83, 0xc4, 0x20, 0x5d, 0xff, 0xe1, 0xc3,
	}
	if !bytes.Equal(text.Data, want) {
		t.Fatalf("text = %x, want %x", text.Data, want)
	}
}

func TestMultipleCallsAndOptionalNOP(t *testing.T) {
	code := []byte{
		0xe8, 0, 0, 0, 0, // no following NOP
		0xe8, 0, 0, 0, 0, 0x90,
		0xc3,
	}
	object, text, _, first := testTransferObject(t, coff.MachineAMD64, code, 0)
	intrinsic := object.GetSymbol(transferSymbol)
	second := &coff.Relocation{Section: text, VirtualAddress: 6, SymbolName: intrinsic.Name, Symbol: intrinsic, Type: coff.RelAMD64Rel32}
	text.Relocations = append(text.Relocations, second)
	report, err := Apply(context.Background(), object, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xff, 0xe1, 0xff, 0xe1, 0xc3}; !bytes.Equal(text.Data, want) {
		t.Fatalf("text = %x, want %x", text.Data, want)
	}
	if len(text.Relocations) != 0 || report.RewrittenCalls != 2 || report.ConsumedNOPs != 1 || len(report.Functions) != 1 || report.Functions[0].Calls != 2 {
		t.Fatalf("calls = report %#v relocs=%#v (first=%p second=%p)", report, text.Relocations, first, second)
	}
}

func TestApplyX86AndAbsentIntrinsicAreNoOps(t *testing.T) {
	x86Object, err := coff.NewObject(coff.MachineI386)
	if err != nil {
		t.Fatal(err)
	}
	conflicting := Options{Disassembler: &testDecoder{}, Factory: func(context.Context, x86.Mode) (x86.Disassembler, error) { return nil, nil }}
	if report, err := Apply(context.Background(), x86Object, conflicting); err != nil || report.RewrittenCalls != 0 || report.BytesBefore != 0 || len(report.Functions) != 0 {
		t.Fatalf("x86 no-op = %#v, %v", report, err)
	}

	x64Object, err := coff.NewObject(coff.MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", []byte{0xc3})
	if err := x64Object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	if err := x64Object.AddSymbol(coff.NewFunctionSymbol(text, "go", 0)); err != nil {
		t.Fatal(err)
	}
	report, err := Apply(context.Background(), x64Object, conflicting)
	if err != nil || report.BytesBefore != 1 || report.BytesAfter != 1 || !bytes.Equal(text.Data, []byte{0xc3}) {
		t.Fatalf("absent intrinsic no-op = %#v, %v, %x", report, err, text.Data)
	}
}

func TestCallAndPrologueFailuresAreTypedAndTransactional(t *testing.T) {
	t.Run("wrong opcode", func(t *testing.T) {
		code := []byte{0xe9, 0, 0, 0, 0, 0xc3}
		object, text, _, relocation := testTransferObject(t, coff.MachineAMD64, code, 0)
		assertTransactionalError(t, object, text, relocation, ErrUnsupportedCall)
	})

	t.Run("wrong relocation", func(t *testing.T) {
		code := []byte{0xe8, 0, 0, 0, 0, 0xc3}
		object, text, _, relocation := testTransferObject(t, coff.MachineAMD64, code, 0)
		relocation.Type = coff.RelAMD64Addr32NB
		assertTransactionalError(t, object, text, relocation, ErrUnsupportedCall)
	})

	t.Run("noncanonical push", func(t *testing.T) {
		code := []byte{0x48, 0x53, 0xe8, 0, 0, 0, 0, 0xc3}
		object, text, _, relocation := testTransferObject(t, coff.MachineAMD64, code, 2)
		assertTransactionalError(t, object, text, relocation, ErrUnprovenPrologue)
	})

	t.Run("stack mutation after frame pointer", func(t *testing.T) {
		code := []byte{
			0x55, 0x48, 0x89, 0xe5, // push rbp; mov rbp,rsp
			0x48, 0x83, 0xec, 0x20,
			0xe8, 0, 0, 0, 0, 0xc3,
		}
		object, text, _, relocation := testTransferObject(t, coff.MachineAMD64, code, 8)
		assertTransactionalError(t, object, text, relocation, ErrUnprovenPrologue)
	})

	t.Run("stack nonvolatile save", func(t *testing.T) {
		code := []byte{
			0x48, 0x83, 0xec, 0x20,
			0x48, 0x89, 0x5c, 0x24, 0x08,
			0xe8, 0, 0, 0, 0, 0xc3,
		}
		object, text, _, relocation := testTransferObject(t, coff.MachineAMD64, code, 9)
		assertTransactionalError(t, object, text, relocation, ErrUnprovenPrologue)
	})
}

func TestBranchRelocationSymbolAndUnwindRepair(t *testing.T) {
	code := []byte{
		0x53, 0x48, 0x83, 0xec, 0x20,
		0x75, 0x06, // jne old offset 13
		0xe8, 0, 0, 0, 0, 0x90,
		0xc3,
		0xe8, 0, 0, 0, 0, 0xc3,
	}
	object, text, function, transferRelocation := testTransferObject(t, coff.MachineAMD64, code, 7)
	external := &coff.Symbol{Name: "external", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(external); err != nil {
		t.Fatal(err)
	}
	externalRelocation := &coff.Relocation{Section: text, VirtualAddress: 15, SymbolName: external.Name, Symbol: external, Type: coff.RelAMD64Rel32}
	text.Relocations = append(text.Relocations, externalRelocation)
	function.AuxiliaryRecords = [][]byte{make([]byte, 18)}

	pdata := coff.NewSection(".pdata", make([]byte, 12))
	binary.LittleEndian.PutUint32(pdata.Data[4:8], uint32(len(code)))
	if err := object.AddSection(pdata); err != nil {
		t.Fatal(err)
	}
	textSymbol := object.GetSymbol(".text")
	pdata.Relocations = []*coff.Relocation{
		{Section: pdata, VirtualAddress: 0, SymbolName: textSymbol.Name, Symbol: textSymbol, Type: coff.RelAMD64Addr32NB},
		{Section: pdata, VirtualAddress: 4, SymbolName: textSymbol.Name, Symbol: textSymbol, Type: coff.RelAMD64Addr32NB},
	}

	_, err := Apply(context.Background(), object, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := []byte{
		0x53, 0x48, 0x83, 0xec, 0x20,
		0x75, 0x07,
		0x48, 0x83, 0xc4, 0x20, 0x5b, 0xff, 0xe1,
		0xc3,
	}
	if !bytes.HasPrefix(text.Data, wantPrefix) {
		t.Fatalf("text prefix = %x, want %x", text.Data, wantPrefix)
	}
	if len(text.Relocations) != 1 || text.Relocations[0] != externalRelocation || externalRelocation.VirtualAddress != 16 {
		t.Fatalf("surviving relocations = %#v (transfer=%p external=%p)", text.Relocations, transferRelocation, externalRelocation)
	}
	if got := binary.LittleEndian.Uint32(pdata.Data[4:8]); got != uint32(len(text.Data)) {
		t.Fatalf("pdata end = %d, want %d", got, len(text.Data))
	}
	if got := binary.LittleEndian.Uint32(function.AuxiliaryRecords[0][4:8]); got != uint32(len(text.Data)) {
		t.Fatalf("function auxiliary size = %d, want %d", got, len(text.Data))
	}
}

func TestRIPRelativeLocalLabelRepairAndUnsupportedForm(t *testing.T) {
	code := []byte{
		0x48, 0x8d, 0x05, 0x07, 0, 0, 0, // lea rax, [rip+7] -> old offset 14
		0xe8, 0, 0, 0, 0, 0x90, 0xc3,
		0xc3, // embedded data at offset 14
	}
	object, text, _, _ := testTransferObject(t, coff.MachineAMD64, code, 7)
	literal := coff.NewDataSymbol(text, "literal", 14)
	if err := object.AddSymbol(literal); err != nil {
		t.Fatal(err)
	}
	_, err := Apply(context.Background(), object, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x48, 0x8d, 0x05, 0x03, 0, 0, 0,
		0xff, 0xe1, 0xc3, 0xc3,
	}
	if !bytes.Equal(text.Data, want) || literal.Value != 10 {
		t.Fatalf("RIP repair = %x literal=%d, want %x literal=10", text.Data, literal.Value, want)
	}

	unsupported := []byte{0x8b, 0x05, 0x06, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x90, 0xc3}
	object, text, _, relocation := testTransferObject(t, coff.MachineAMD64, unsupported, 6)
	assertTransactionalError(t, object, text, relocation, ErrUnsupportedFlow)
}

func TestXBEGINFailsClosedTransactionally(t *testing.T) {
	code := []byte{0xe8, 0, 0, 0, 0, 0x90, 0xc7, 0xf8, 0, 0, 0, 0, 0xc3}
	object, text, _, relocation := testTransferObject(t, coff.MachineAMD64, code, 0)
	decoder := &testDecoder{instructions: []x86.Instruction{
		{Address: 0, Bytes: []byte{0xe8, 0, 0, 0, 0}, Mnemonic: "call", Operands: "0x5"},
		{Address: 5, Bytes: []byte{0x90}, Mnemonic: "nop"},
		{Address: 6, Bytes: []byte{0xc7, 0xf8, 0, 0, 0, 0}, Mnemonic: "xbegin", Operands: "0xc"},
		{Address: 12, Bytes: []byte{0xc3}, Mnemonic: "ret"},
	}}
	before := append([]byte(nil), text.Data...)
	_, err := Apply(context.Background(), object, Options{Disassembler: decoder})
	if !errors.Is(err, ErrUnsupportedFlow) || !bytes.Equal(text.Data, before) || relocation.VirtualAddress != 1 {
		t.Fatalf("XBEGIN = %v text=%x relocation=%d", err, text.Data, relocation.VirtualAddress)
	}
}

func TestBranchRelaxationAndShortOnlyFailure(t *testing.T) {
	build := func(branch byte) ([]byte, uint32) {
		code := bytes.Repeat([]byte{0x53}, 130)
		code = append(code, branch, 0x06)
		call := uint32(len(code))
		code = append(code, 0xe8, 0, 0, 0, 0, 0x90, 0xc3)
		return code, call
	}
	code, call := build(0x75)
	object, text, _, _ := testTransferObject(t, coff.MachineAMD64, code, call)
	report, err := Apply(context.Background(), object, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.RelaxedBranches != 1 || !bytes.Equal(text.Data[130:132], []byte{0x0f, 0x85}) {
		t.Fatalf("branch/report = %x / %#v", text.Data[130:136], report)
	}

	code, call = build(0xe2)
	object, text, _, relocation := testTransferObject(t, coff.MachineAMD64, code, call)
	assertTransactionalError(t, object, text, relocation, ErrBranchRange)
}

func TestExistingUnwindWithoutRelocationsFailsTransactionally(t *testing.T) {
	code := []byte{0xe8, 0, 0, 0, 0, 0x90, 0xc3}
	object, text, _, relocation := testTransferObject(t, coff.MachineAMD64, code, 0)
	pdata := coff.NewSection(".pdata", make([]byte, 12))
	if err := object.AddSection(pdata); err != nil {
		t.Fatal(err)
	}
	assertTransactionalError(t, object, text, relocation, ErrUnsupportedUnwind)
}

func TestLifecycleCancellationValidationAndConcurrency(t *testing.T) {
	if _, err := Apply(nil, nil, Options{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context = %v", err)
	}
	if _, err := Apply(context.Background(), nil, Options{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil object = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	object, _, _, _ := testTransferObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, 0)
	if _, err := Apply(ctx, object, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled = %v", err)
	}
	if _, err := Apply(context.Background(), object, Options{Disassembler: &testDecoder{}, Factory: func(context.Context, x86.Mode) (x86.Disassembler, error) { return nil, nil }}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("decoder option conflict = %v", err)
	}

	instructions := simpleTransferInstructions()
	decoder := &testDecoder{instructions: instructions}
	object, _, _, _ = testTransferObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0x90, 0xc3}, 0)
	_, err := Apply(context.Background(), object, Options{Factory: func(_ context.Context, mode x86.Mode) (x86.Disassembler, error) {
		if mode != x86.Mode64 {
			t.Fatalf("mode = %v", mode)
		}
		return decoder, nil
	}})
	if err != nil || decoder.closed != 1 {
		t.Fatalf("factory Apply = %v, closes=%d", err, decoder.closed)
	}

	callerDecoder := &testDecoder{instructions: simpleTransferInstructions()}
	object, _, _, _ = testTransferObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0x90, 0xc3}, 0)
	if _, err := Apply(context.Background(), object, Options{Disassembler: callerDecoder}); err != nil || callerDecoder.closed != 0 {
		t.Fatalf("caller-owned decoder = %v, closes=%d", err, callerDecoder.closed)
	}

	closeFailure := errors.New("close failed")
	closingDecoder := &testDecoder{instructions: simpleTransferInstructions(), closeErr: closeFailure}
	object, text, _, relocation := testTransferObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0x90, 0xc3}, 0)
	before := append([]byte(nil), text.Data...)
	if _, err := Apply(context.Background(), object, Options{Factory: func(context.Context, x86.Mode) (x86.Disassembler, error) {
		return closingDecoder, nil
	}}); !errors.Is(err, closeFailure) || !bytes.Equal(text.Data, before) || relocation.VirtualAddress != 1 {
		t.Fatalf("close failure = %v text=%x relocation=%d", err, text.Data, relocation.VirtualAddress)
	}

	const workers = 8
	var wait sync.WaitGroup
	errorsOut := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			candidate, _, _, _ := testTransferObjectNoFatal(coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0x90, 0xc3}, 0)
			_, err := Apply(context.Background(), candidate, Options{Disassembler: &testDecoder{instructions: simpleTransferInstructions()}})
			errorsOut <- err
		}()
	}
	wait.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertTransactionalError(t *testing.T, object *coff.Object, text *coff.Section, relocation *coff.Relocation, target error) {
	t.Helper()
	beforeText := append([]byte(nil), text.Data...)
	beforeRelocations := append([]*coff.Relocation(nil), text.Relocations...)
	beforeVA := relocation.VirtualAddress
	_, err := Apply(context.Background(), object, Options{})
	if !errors.Is(err, target) {
		t.Fatalf("Apply error = %v, want errors.Is(_, %v)", err, target)
	}
	if !bytes.Equal(text.Data, beforeText) || fmt.Sprint(text.Relocations) != fmt.Sprint(beforeRelocations) || relocation.VirtualAddress != beforeVA {
		t.Fatalf("failed Apply mutated object: text=%x relocs=%#v VA=%d", text.Data, text.Relocations, relocation.VirtualAddress)
	}
}

type testDecoder struct {
	instructions []x86.Instruction
	err          error
	closeErr     error
	closed       int
}

func (d *testDecoder) Disassemble(context.Context, []byte, uint64) ([]x86.Instruction, error) {
	result := make([]x86.Instruction, len(d.instructions))
	copy(result, d.instructions)
	return result, d.err
}

func (d *testDecoder) Close(context.Context) error {
	d.closed++
	return d.closeErr
}

func simpleTransferInstructions() []x86.Instruction {
	return []x86.Instruction{
		{Address: 0, Bytes: []byte{0xe8, 0, 0, 0, 0}, Mnemonic: "call", Operands: "0x5"},
		{Address: 5, Bytes: []byte{0x90}, Mnemonic: "nop"},
		{Address: 6, Bytes: []byte{0xc3}, Mnemonic: "ret"},
	}
}

func testTransferObject(t *testing.T, machine coff.Machine, code []byte, call uint32) (*coff.Object, *coff.Section, *coff.Symbol, *coff.Relocation) {
	t.Helper()
	object, text, function, relocation := testTransferObjectNoFatal(machine, code, call)
	if object == nil {
		t.Fatal("failed to construct test COFF object")
	}
	return object, text, function, relocation
}

func testTransferObjectNoFatal(machine coff.Machine, code []byte, call uint32) (*coff.Object, *coff.Section, *coff.Symbol, *coff.Relocation) {
	object, err := coff.NewObject(machine)
	if err != nil {
		return nil, nil, nil, nil
	}
	text := coff.NewSection(".text", code)
	if err := object.AddSection(text); err != nil {
		return nil, nil, nil, nil
	}
	function := coff.NewFunctionSymbol(text, "go", 0)
	if err := object.AddSymbol(function); err != nil {
		return nil, nil, nil, nil
	}
	intrinsic := &coff.Symbol{Name: transferSymbol, Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(intrinsic); err != nil {
		return nil, nil, nil, nil
	}
	relocation := &coff.Relocation{Section: text, VirtualAddress: call + 1, SymbolName: intrinsic.Name, Symbol: intrinsic, Type: coff.RelAMD64Rel32}
	text.Relocations = append(text.Relocations, relocation)
	return object, text, function, relocation
}
