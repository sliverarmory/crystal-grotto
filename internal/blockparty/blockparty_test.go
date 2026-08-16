// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package blockparty

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestApplyExactUpstreamBlockPermutationX64AndX86(t *testing.T) {
	for _, machine := range []coff.Machine{coff.MachineAMD64, coff.MachineI386} {
		t.Run(machine.String(), func(t *testing.T) {
			object, text, function := testObject(t, machine, []byte{0x74, 0x02, 0x90, 0xc3, 0x90, 0xc3})
			function.AuxiliaryRecords = [][]byte{make([]byte, 18)}
			report, err := Apply(context.Background(), object, Options{Random: bytes.NewReader([]byte{0, 0, 0, 0})})
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			want := []byte{0x74, 0x02, 0xeb, 0x02, 0x90, 0xc3, 0x90, 0xc3, 0xeb, 0xfa}
			if !bytes.Equal(text.Data, want) {
				t.Fatalf("text = %x, want %x", text.Data, want)
			}
			if report.EligibleFunctions != 1 || report.ShuffledFunctions != 1 || report.Blocks != 3 || report.RandomDraws != 1 || report.InsertedJumps != 2 {
				t.Fatalf("report = %#v", report)
			}
			if got, want := fmt.Sprint(report.Functions), "[{go [0 2 4] [0 4 2]}]"; got != want {
				t.Fatalf("functions = %s, want %s", got, want)
			}
			if function.Value != 0 || binary.LittleEndian.Uint32(function.AuxiliaryRecords[0][4:8]) != uint32(len(want)) {
				t.Fatalf("function value/size = %d/%d", function.Value, binary.LittleEndian.Uint32(function.AuxiliaryRecords[0][4:8]))
			}
			clone := report.Clone()
			clone.Functions[0].SelectedOrder[0] = 99
			if report.Functions[0].SelectedOrder[0] != 0 {
				t.Fatal("Report.Clone aliases selected order")
			}
		})
	}
}

func TestApplyHealsOnlyUnsymbolizedLocalJump(t *testing.T) {
	object, text, function := testObject(t, coff.MachineAMD64, []byte{0xeb, 0x00, 0xc3})
	function.AuxiliaryRecords = [][]byte{make([]byte, 18)}
	report, err := Apply(context.Background(), object, Options{Seed: seed(1)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(text.Data, []byte{0xc3}) || report.RemovedJumps != 1 {
		t.Fatalf("healed = %x report=%#v", text.Data, report)
	}
	if binary.LittleEndian.Uint32(function.AuxiliaryRecords[0][4:8]) != 1 {
		t.Fatalf("aux size = %d", binary.LittleEndian.Uint32(function.AuxiliaryRecords[0][4:8]))
	}

	object, text, _ = testObject(t, coff.MachineAMD64, []byte{0xeb, 0x00, 0xc3})
	if err := object.AddSymbol(coff.NewDataSymbol(text, "target", 2)); err != nil {
		t.Fatal(err)
	}
	report, err = Apply(context.Background(), object, Options{Seed: seed(1)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(text.Data, []byte{0xeb, 0x00, 0xc3}) || report.RemovedJumps != 0 {
		t.Fatalf("symbolized jump = %x report=%#v", text.Data, report)
	}
}

func TestRelocationAndCrossSectionAddendRebasing(t *testing.T) {
	code := []byte{0x74, 0x06, 0xe8, 0, 0, 0, 0, 0xc3, 0x90, 0xc3}
	object, text, _ := testObject(t, coff.MachineAMD64, code)
	external := &coff.Symbol{Name: "external", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(external); err != nil {
		t.Fatal(err)
	}
	callRelocation := &coff.Relocation{Section: text, VirtualAddress: 3, SymbolName: external.Name, Symbol: external, Type: coff.RelAMD64Rel32}
	text.Relocations = append(text.Relocations, callRelocation)
	rdata := coff.NewSection(".rdata", make([]byte, 4))
	if err := object.AddSection(rdata); err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(rdata.Data, 2)
	textSymbol := object.GetSymbol(".text")
	rdataRelocation := &coff.Relocation{Section: rdata, VirtualAddress: 0, SymbolName: ".text", Symbol: textSymbol, Type: coff.RelAMD64Addr32NB}
	rdata.Relocations = append(rdata.Relocations, rdataRelocation)

	_, err := Apply(context.Background(), object, Options{Random: bytes.NewReader([]byte{0, 0, 0, 0})})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x74, 0x02, 0xeb, 0x02, 0x90, 0xc3, 0xe8, 0, 0, 0, 0, 0xc3, 0xeb, 0xf6}
	if !bytes.Equal(text.Data, want) {
		t.Fatalf("text = %x, want %x", text.Data, want)
	}
	if callRelocation.VirtualAddress != 7 || callRelocation.Section != text {
		t.Fatalf("call relocation = %#v", callRelocation)
	}
	if got := binary.LittleEndian.Uint32(rdata.Data); got != 6 {
		t.Fatalf("rebased .text addend = %d, want 6", got)
	}
	if rdataRelocation.VirtualAddress != 0 {
		t.Fatalf("rdata relocation moved to %d", rdataRelocation.VirtualAddress)
	}
}

func TestRIPRelativeLocalLabelRepair(t *testing.T) {
	code := []byte{
		0x74, 0x02,
		0x90, 0xc3,
		0x48, 0x8d, 0x05, 0x01, 0, 0, 0, 0xc3,
		0xc3,
	}
	object, text, _ := testObject(t, coff.MachineAMD64, code)
	dataSymbol := coff.NewDataSymbol(text, "literal", 12)
	if err := object.AddSymbol(dataSymbol); err != nil {
		t.Fatal(err)
	}
	_, err := Apply(context.Background(), object, Options{Random: bytes.NewReader([]byte{0, 0, 0, 0})})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x74, 0x02, 0xeb, 0x08,
		0x48, 0x8d, 0x05, 0x05, 0, 0, 0, 0xc3,
		0x90, 0xc3, 0xeb, 0xf4,
		0xc3,
	}
	if !bytes.Equal(text.Data, want) {
		t.Fatalf("text = %x, want %x", text.Data, want)
	}
	if dataSymbol.Value != 16 {
		t.Fatalf("literal = %d, want 16", dataSymbol.Value)
	}
	displacement := int32(binary.LittleEndian.Uint32(text.Data[7:11]))
	if target := int32(11) + displacement; target != 16 {
		t.Fatalf("LEA target = %d, want 16", target)
	}
}

func TestRIPRelativeFormsFailClosedUnlessRelocationFieldIsProvable(t *testing.T) {
	code := []byte{0x8b, 0x05, 0, 0, 0, 0, 0xc3} // mov eax, dword ptr [rip]
	for _, test := range []struct {
		name             string
		relocationOffset *uint32
		wantError        bool
	}{
		{name: "unrelocated", wantError: true},
		{name: "relocation_at_displacement", relocationOffset: uint32ptr(2)},
		{name: "relocation_not_at_displacement", relocationOffset: uint32ptr(1), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			object, text, _ := testObject(t, coff.MachineAMD64, code)
			if test.relocationOffset != nil {
				external := &coff.Symbol{Name: "external", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
				if err := object.AddSymbol(external); err != nil {
					t.Fatal(err)
				}
				text.Relocations = append(text.Relocations, &coff.Relocation{
					Section: text, VirtualAddress: *test.relocationOffset,
					SymbolName: external.Name, Symbol: external, Type: coff.RelAMD64Rel32,
				})
			}
			before := append([]byte(nil), text.Data...)
			_, err := Apply(context.Background(), object, Options{Seed: seed(1)})
			if test.wantError {
				if !errors.Is(err, ErrUnsupportedSemantic) {
					t.Fatalf("Apply error = %v, want unsupported semantic", err)
				}
				if !bytes.Equal(text.Data, before) {
					t.Fatal("failed RIP-relative pass mutated .text")
				}
				return
			}
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if !bytes.Equal(text.Data, before) {
				t.Fatalf("relocated RIP-relative bytes = %x, want %x", text.Data, before)
			}
		})
	}
}

func TestUnsupportedRelativeEncodingsAreTransactional(t *testing.T) {
	tests := []struct {
		name        string
		code        []byte
		instruction x86.Instruction
	}{
		{
			name:        "xbegin",
			code:        []byte{0xc7, 0xf8, 0, 0, 0, 0, 0xc3},
			instruction: x86.Instruction{Address: 0, Bytes: []byte{0xc7, 0xf8, 0, 0, 0, 0}, Mnemonic: "xbegin", Operands: "0x6"},
		},
		{
			name:        "prefixed_jump",
			code:        []byte{0xf2, 0xe9, 0, 0, 0, 0, 0xc3},
			instruction: x86.Instruction{Address: 0, Bytes: []byte{0xf2, 0xe9, 0, 0, 0, 0}, Mnemonic: "bnd jmp", Operands: "0x6"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object, text, _ := testObject(t, coff.MachineAMD64, test.code)
			decoder := &testDecoder{instructions: []x86.Instruction{
				test.instruction,
				{Address: uint64(len(test.instruction.Bytes)), Bytes: []byte{0xc3}, Mnemonic: "ret"},
			}}
			before := append([]byte(nil), text.Data...)
			_, err := Apply(context.Background(), object, Options{Disassembler: decoder, Seed: seed(1)})
			if !errors.Is(err, ErrUnsupportedSemantic) {
				t.Fatalf("Apply error = %v, want unsupported semantic", err)
			}
			var unsupportedError *UnsupportedError
			if !errors.As(err, &unsupportedError) || unsupportedError.Offset != 0 || unsupportedError.Function != "go" {
				t.Fatalf("unsupported error = %T %#v", err, unsupportedError)
			}
			if !bytes.Equal(text.Data, before) {
				t.Fatal("failed relative-control-flow pass mutated .text")
			}
		})
	}
}

func TestExistingPDATARebasedOrRejectedTransactionally(t *testing.T) {
	build := func(withRelocations bool) (*coff.Object, *coff.Section, *coff.Section) {
		object, text, _ := testObject(t, coff.MachineAMD64, []byte{0x74, 0x02, 0x90, 0xc3, 0x90, 0xc3})
		pdata := coff.NewSection(".pdata", make([]byte, 12))
		binary.LittleEndian.PutUint32(pdata.Data[4:8], 6)
		if err := object.AddSection(pdata); err != nil {
			t.Fatal(err)
		}
		if withRelocations {
			textSymbol := object.GetSymbol(".text")
			pdata.Relocations = []*coff.Relocation{
				{Section: pdata, VirtualAddress: 0, SymbolName: ".text", Symbol: textSymbol, Type: coff.RelAMD64Addr32NB},
				{Section: pdata, VirtualAddress: 4, SymbolName: ".text", Symbol: textSymbol, Type: coff.RelAMD64Addr32NB},
			}
		}
		return object, text, pdata
	}

	object, _, pdata := build(true)
	if _, err := Apply(context.Background(), object, Options{Random: bytes.NewReader([]byte{0, 0, 0, 0})}); err != nil {
		t.Fatal(err)
	}
	if begin, end := binary.LittleEndian.Uint32(pdata.Data[0:4]), binary.LittleEndian.Uint32(pdata.Data[4:8]); begin != 0 || end != 10 {
		t.Fatalf("runtime function = [%d,%d), want [0,10)", begin, end)
	}

	object, text, _ := build(false)
	before := append([]byte(nil), text.Data...)
	_, err := Apply(context.Background(), object, Options{Random: bytes.NewReader([]byte{0, 0, 0, 0})})
	if !errors.Is(err, ErrUnsupportedUnwind) {
		t.Fatalf("missing pdata relocations = %v", err)
	}
	var unwindError *UnwindError
	if !errors.As(err, &unwindError) || unwindError.Section != ".pdata" {
		t.Fatalf("unwind error = %T %#v", err, unwindError)
	}
	if !bytes.Equal(text.Data, before) {
		t.Fatal("failed unwind validation mutated text")
	}

	// A permutation can move runtime-function boundaries without changing the
	// total .text length. Existing pdata still needs relocations in that case.
	object, text, _ = testObject(t, coff.MachineAMD64, []byte{0xff, 0xe1, 0xff, 0xe1, 0xc3})
	pdata = coff.NewSection(".pdata", make([]byte, 12))
	if err := object.AddSection(pdata); err != nil {
		t.Fatal(err)
	}
	before = append([]byte(nil), text.Data...)
	_, err = Apply(context.Background(), object, Options{Random: bytes.NewReader([]byte{0, 0, 0, 0})})
	if !errors.Is(err, ErrUnsupportedUnwind) || !bytes.Equal(text.Data, before) {
		t.Fatalf("same-length pdata error = %v text=%x", err, text.Data)
	}

	// Conversely, untouched code does not require synthetic pdata relocations.
	object, _, _ = testObject(t, coff.MachineAMD64, []byte{0xc3})
	pdata = coff.NewSection(".pdata", make([]byte, 12))
	if err := object.AddSection(pdata); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), object, Options{Seed: seed(1)}); err != nil {
		t.Fatalf("no-op pdata Apply: %v", err)
	}
}

func TestShortBranchRelaxationAndLoopFailureAreTransactional(t *testing.T) {
	makeCode := func(opcode byte) []byte {
		code := []byte{0x75, 0x00, opcode, 0x00}
		code = append(code, bytes.Repeat([]byte{0x90}, 130)...)
		return append(code, 0xc3)
	}
	object, text, _ := testObject(t, coff.MachineAMD64, makeCode(0xeb))
	report, err := Apply(context.Background(), object, Options{Random: bytes.NewReader([]byte{0, 0, 0, 0})})
	if err != nil {
		t.Fatal(err)
	}
	if report.RelaxedBranches < 2 {
		t.Fatalf("relaxed branches = %d", report.RelaxedBranches)
	}
	if len(text.Data) <= len(makeCode(0xeb)) || !bytes.Contains(text.Data, []byte{0xe9}) {
		t.Fatalf("relaxed text = %x", text.Data)
	}

	object, text, _ = testObject(t, coff.MachineAMD64, makeCode(0xe2))
	before := append([]byte(nil), text.Data...)
	_, err = Apply(context.Background(), object, Options{Random: bytes.NewReader([]byte{0, 0, 0, 0})})
	if !errors.Is(err, ErrBranchRange) {
		t.Fatalf("loop error = %v", err)
	}
	var rangeError *BranchRangeError
	if !errors.As(err, &rangeError) || rangeError.Offset != 2 {
		t.Fatalf("loop error type = %T %#v", err, rangeError)
	}
	if !bytes.Equal(text.Data, before) {
		t.Fatal("failed loop pass mutated .text")
	}
}

func TestInputUnsupportedAndRandomFailureValidation(t *testing.T) {
	object, text, _ := testObject(t, coff.MachineAMD64, []byte{0x74, 0x02, 0x90, 0xc3, 0x90, 0xc3})
	before := append([]byte(nil), text.Data...)
	_, err := Apply(context.Background(), object, Options{Random: bytes.NewReader(nil)})
	if !errors.Is(err, io.EOF) || !bytes.Equal(text.Data, before) {
		t.Fatalf("random failure = %v text=%x", err, text.Data)
	}
	if _, err := Apply(nil, object, Options{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context = %v", err)
	}
	if _, err := Apply(context.Background(), nil, Options{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil object = %v", err)
	}
	if _, err := Apply(context.Background(), object, Options{Random: bytes.NewReader(nil), Seed: seed(1)}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("random conflict = %v", err)
	}

	misaligned, badText, _ := testObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3})
	if err := misaligned.AddSymbol(coff.NewDataSymbol(badText, "inside", 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), misaligned, Options{Seed: seed(1)}); !errors.Is(err, ErrMalformedObject) {
		t.Fatalf("misaligned symbol = %v", err)
	}

	fakeObject, _, _ := testObject(t, coff.MachineAMD64, []byte{0x90})
	decoder := &testDecoder{instructions: []x86.Instruction{{Address: 0, Bytes: []byte{0x90}, Mnemonic: "jmp", Operands: "0x1"}}}
	_, err = Apply(context.Background(), fakeObject, Options{Disassembler: decoder, Seed: seed(1)})
	if !errors.Is(err, ErrUnsupportedSemantic) {
		t.Fatalf("unsupported direct flow = %v", err)
	}
	if decoder.closed != 0 {
		t.Fatalf("caller decoder closed %d times", decoder.closed)
	}

	mismatchObject, mismatchText, _ := testObject(t, coff.MachineAMD64, []byte{0x90})
	mismatchDecoder := &testDecoder{instructions: []x86.Instruction{{Address: 0, Bytes: []byte{0x91}, Mnemonic: "xchg", Operands: "eax, ecx"}}}
	_, err = Apply(context.Background(), mismatchObject, Options{Disassembler: mismatchDecoder, Seed: seed(1)})
	if !errors.Is(err, ErrMalformedObject) || !bytes.Equal(mismatchText.Data, []byte{0x90}) {
		t.Fatalf("decoder mismatch = %v text=%x", err, mismatchText.Data)
	}

	badRelocationObject, badRelocationText, _ := testObject(t, coff.MachineAMD64, []byte{0xc3})
	badRelocationText.Relocations = append(badRelocationText.Relocations, &coff.Relocation{Section: badRelocationText, VirtualAddress: 0, SymbolName: "missing", Type: coff.RelAMD64Rel32})
	if _, err := Apply(context.Background(), badRelocationObject, Options{Seed: seed(1)}); !errors.Is(err, ErrMalformedObject) {
		t.Fatalf("missing relocation symbol = %v", err)
	}
}

func TestFactoryLifecycleCancellationAndConcurrentUse(t *testing.T) {
	object, _, _ := testObject(t, coff.MachineAMD64, []byte{0xc3})
	decoder := &testDecoder{instructions: []x86.Instruction{{Address: 0, Bytes: []byte{0xc3}, Mnemonic: "ret"}}}
	_, err := Apply(context.Background(), object, Options{Seed: seed(1), Factory: func(_ context.Context, mode x86.Mode) (x86.Disassembler, error) {
		if mode != x86.Mode64 {
			t.Fatalf("mode = %v", mode)
		}
		return decoder, nil
	}})
	if err != nil || decoder.closed != 1 {
		t.Fatalf("factory Apply = %v, closes=%d", err, decoder.closed)
	}
	closeFailure := errors.New("close failed")
	closingDecoder := &testDecoder{instructions: []x86.Instruction{{Address: 0, Bytes: []byte{0xc3}, Mnemonic: "ret"}}, closeErr: closeFailure}
	if _, err := Apply(context.Background(), object, Options{Seed: seed(1), Factory: func(context.Context, x86.Mode) (x86.Disassembler, error) {
		return closingDecoder, nil
	}}); !errors.Is(err, closeFailure) {
		t.Fatalf("close failure = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Apply(ctx, object, Options{Seed: seed(1)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled = %v", err)
	}

	const workers = 8
	var wait sync.WaitGroup
	errorsOut := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			candidate, _, _ := testObjectNoFatal(coff.MachineAMD64, []byte{0x74, 0x02, 0x90, 0xc3, 0x90, 0xc3})
			decoder := &testDecoder{instructions: []x86.Instruction{
				{Address: 0, Bytes: []byte{0x74, 0x02}, Mnemonic: "je", Operands: "0x4"},
				{Address: 2, Bytes: []byte{0x90}, Mnemonic: "nop"},
				{Address: 3, Bytes: []byte{0xc3}, Mnemonic: "ret"},
				{Address: 4, Bytes: []byte{0x90}, Mnemonic: "nop"},
				{Address: 5, Bytes: []byte{0xc3}, Mnemonic: "ret"},
			}}
			_, err := Apply(context.Background(), candidate, Options{Disassembler: decoder, Seed: seed(7)})
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

func TestJavaRandomAndShuffleVectors(t *testing.T) {
	random := newJavaRandom(0)
	for index, want := range []int{60, 48, 29, 47, 15} {
		got, draws, err := random.nextInt(100)
		if err != nil || draws != 1 || got != want {
			t.Fatalf("nextInt[%d] = %d/%d/%v, want %d/1/nil", index, got, draws, err, want)
		}
	}

	blocks := []*basicBlock{{leader: 0}, {leader: 1}, {leader: 2}, {leader: 3}}
	draws, err := shuffleBlocks(blocks, newJavaRandom(0))
	if err != nil || draws != 3 {
		t.Fatalf("shuffle = draws %d, error %v", draws, err)
	}
	got := make([]uint32, len(blocks))
	for index, block := range blocks {
		got[index] = block.leader
	}
	if want := "[3 0 1 2]"; fmt.Sprint(got) != want {
		t.Fatalf("shuffle = %v, want %s", got, want)
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

func seed(value int64) *int64 { return &value }

func uint32ptr(value uint32) *uint32 { return &value }

func testObject(t *testing.T, machine coff.Machine, code []byte) (*coff.Object, *coff.Section, *coff.Symbol) {
	t.Helper()
	object, text, function := testObjectNoFatal(machine, code)
	if object == nil {
		t.Fatal("failed to build object")
	}
	return object, text, function
}

func testObjectNoFatal(machine coff.Machine, code []byte) (*coff.Object, *coff.Section, *coff.Symbol) {
	object, err := coff.NewObject(machine)
	if err != nil {
		return nil, nil, nil
	}
	text := coff.NewSection(".text", code)
	if err := object.AddSection(text); err != nil {
		return nil, nil, nil
	}
	function := coff.NewFunctionSymbol(text, "go", 0)
	if err := object.AddSymbol(function); err != nil {
		return nil, nil, nil
	}
	return object, text, function
}
