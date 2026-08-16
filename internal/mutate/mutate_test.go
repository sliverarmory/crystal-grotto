// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package mutate

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"reflect"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestApplyExactX86Vector(t *testing.T) {
	input := mustHex(t,
		"b844332211"+ // mov eax,11223344h
			"81f988776655"+ // cmp ecx,55667788h
			"c745fc78563412"+ // mov dword ptr [ebp-4],12345678h
			"6868245713"+ // push 13572468h
			"c3")
	object, text, _ := fixture(t, coff.MachineI386, input)
	report, err := Apply(context.Background(), object, Options{
		Magic:  []uint32{0x1000, 0x20},
		Random: int32Stream(0, 1, 2, 3),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := mustHex(t,
		"b8442322110500100000"+
			"53bb6877665583c32039d95b"+
			"53bb7846341281c300100000895dfc5b"+
			"53bb4824571383c320871c24"+
			"c3")
	if !bytes.Equal(text.Data, want) {
		t.Fatalf(".text = %x\n want = %x", text.Data, want)
	}
	if report != (Report{MutatedInstructions: 4, RandomDraws: 4}) {
		t.Fatalf("report = %#v", report)
	}
	assertDisassembles(t, x86.Mode32, text.Data)
}

func TestApplyExactX64Vector(t *testing.T) {
	input := mustHex(t,
		"41b944332211"+ // mov r9d,11223344h
			"49ba8877665544332211"+ // mov r10,1122334455667788h
			"c744242078563412"+ // mov dword ptr [rsp+20h],12345678h
			"4181f868245713"+ // cmp r8d,13572468h
			"c3")
	object, text, _ := fixture(t, coff.MachineAMD64, input)
	report, err := Apply(context.Background(), object, Options{
		Magic:  []uint32{0x20},
		Random: int32Stream(9, 8, 7, 6, 5),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := mustHex(t,
		"41b9243322114183c120"+
			"41ba687766554183c220415241ba243322114183c2204489542404415a"+
			"53bb5856341283c320895c24285b"+
			"53bb4824571383c3204139d85b"+
			"c3")
	if !bytes.Equal(text.Data, want) {
		t.Fatalf(".text = %x\n want = %x", text.Data, want)
	}
	if report != (Report{MutatedInstructions: 4, RandomDraws: 5}) {
		t.Fatalf("report = %#v", report)
	}
	assertDisassembles(t, x86.Mode64, text.Data)
}

func TestApplyMOV64DrawsForUnsafeHalves(t *testing.T) {
	object, text, _ := fixture(t, coff.MachineAMD64, mustHex(t, "48b80100000001000000c3"))
	report, err := Apply(context.Background(), object, Options{Magic: []uint32{0x20}, Random: int32Stream(0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "b80100000050b8010000008944240458c3")
	if !bytes.Equal(text.Data, want) || report.RandomDraws != 2 || report.MutatedInstructions != 1 {
		t.Fatalf("data=%x report=%#v", text.Data, report)
	}
}

func TestApplyCMPExcludesDestinationFromTemporaryRegister(t *testing.T) {
	object, text, _ := fixture(t, coff.MachineI386, mustHex(t, "81fb44332211c3"))
	report, err := Apply(context.Background(), object, Options{Magic: []uint32{0x20}, Random: int32Stream(0)})
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "57bf2433221183c72039fb5fc3")
	if !bytes.Equal(text.Data, want) || report != (Report{MutatedInstructions: 1, RandomDraws: 1}) {
		t.Fatalf("data=%x report=%#v", text.Data, report)
	}
}

func TestApplyX86ESPAdjustmentCanGrowToDisp32(t *testing.T) {
	object, text, _ := fixture(t, coff.MachineI386, mustHex(t, "c744247c78563412c3"))
	if _, err := Apply(context.Background(), object, Options{Magic: []uint32{0x20}, Random: int32Stream(0)}); err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "53bb5856341283c320899c24800000005bc3")
	if !bytes.Equal(text.Data, want) {
		t.Fatalf("data=%x want=%x", text.Data, want)
	}
}

func TestBuildConstantUsesJavaIntegerWrap(t *testing.T) {
	output, draws, err := buildConstant(readerRandom{reader: int32Stream(-1)}, nil, 1, math.MaxInt32, false)
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "b90000008083c1ff")
	if !bytes.Equal(output, want) || draws != 1 {
		t.Fatalf("output=%x draws=%d", output, draws)
	}
}

func TestSafeImmediate32MatchesJavaEdges(t *testing.T) {
	tests := []struct {
		value int32
		want  bool
	}{
		{value: 0xff, want: false},
		{value: 0x100, want: true},
		{value: -0x100, want: true},
		{value: 0x400, want: false},
		{value: -0x400, want: false},
		{value: 0xffff, want: false},
		{value: math.MinInt32, want: false},
		{value: math.MaxInt32, want: true},
	}
	for _, test := range tests {
		if got := safeImmediate32(test.value); got != test.want {
			t.Errorf("safeImmediate32(%d) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestApplySkipsUnsafeImmediateForms(t *testing.T) {
	input := mustHex(t,
		"b8ff000000"+ // <= ff
			"b800040000"+ // multiple of 400h
			"b8ffff0000"+ // explicit usual suspect
			"b800000080"+ // Java Math.abs(MIN_VALUE) remains negative
			"48b80000000000000000"+ // zero imm64
			"c3")
	object, text, _ := fixture(t, coff.MachineAMD64, input)
	report, err := Apply(context.Background(), object, Options{Random: bytes.NewReader(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if report != (Report{}) || !bytes.Equal(text.Data, input) {
		t.Fatalf("data=%x report=%#v", text.Data, report)
	}
}

func TestMagicSelectionMatchesJavaAbsAndModulo(t *testing.T) {
	pool := []uint32{0x11, 0x22, 0x33}
	tests := []struct {
		value int32
		want  int32
	}{
		{value: 0, want: 0x11},
		{value: 1, want: 0x22},
		{value: -2, want: 0x33},
		{value: math.MinInt32, want: 0x11},
	}
	for _, test := range tests {
		got, err := chooseMagic(readerRandom{reader: int32Stream(test.value)}, pool)
		if err != nil || got != test.want {
			t.Fatalf("chooseMagic(%d) = %#x, %v; want %#x", test.value, got, err, test.want)
		}
	}
	value, err := chooseMagic(readerRandom{reader: int32Stream(-123)}, nil)
	if err != nil || value != -123 {
		t.Fatalf("empty-pool magic = %d, %v", value, err)
	}
}

func TestSeedUsesStableJavaRandomSequence(t *testing.T) {
	random := newJavaRandom(0)
	want := []int32{-1155484576, -723955400, 1033096058}
	for index, expected := range want {
		value, err := random.nextInt32()
		if err != nil || value != expected {
			t.Fatalf("draw %d = %d, %v; want %d", index, value, err, expected)
		}
	}
	seed := int64(0)
	object, _, _ := fixture(t, coff.MachineI386, mustHex(t, "b844332211c3"))
	if _, err := Apply(context.Background(), object, Options{Magic: []uint32{0x20, 0x40}, Seed: &seed}); err != nil {
		t.Fatalf("seeded Apply: %v", err)
	}
}

func TestApplySkipsRelocationAndRebasesItAfterEarlierMutation(t *testing.T) {
	object, text, function := fixture(t, coff.MachineI386, mustHex(t, "b844332211bb88776655c3"))
	data := coff.NewSection(".data", make([]byte, 4))
	if err := object.AddSection(data); err != nil {
		t.Fatal(err)
	}
	target := coff.NewDataSymbol(data, "target", 0)
	if err := object.AddSymbol(target); err != nil {
		t.Fatal(err)
	}
	relocation := &coff.Relocation{Section: text, VirtualAddress: 6, SymbolName: target.Name, Symbol: target, Type: coff.RelI386Dir32}
	text.Relocations = []*coff.Relocation{relocation}
	end := coff.NewFunctionSymbol(text, "after", 10)
	if err := object.AddSymbol(end); err != nil {
		t.Fatal(err)
	}

	report, err := Apply(context.Background(), object, Options{Magic: []uint32{0x20}, Random: int32Stream(0)})
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "b8243322110520000000bb88776655c3")
	if !bytes.Equal(text.Data, want) || report.MutatedInstructions != 1 || report.SkippedRelocations != 1 {
		t.Fatalf("data=%x report=%#v", text.Data, report)
	}
	if relocation.VirtualAddress != 11 || relocation.Section != text || end.Value != 15 || function.Value != 0 {
		t.Fatalf("reloc=%#x end=%#x entry=%#x", relocation.VirtualAddress, end.Value, function.Value)
	}
}

func TestApplyRepairsAndWidensShortBranch(t *testing.T) {
	input := []byte{0xeb, 0x7d}
	for index := 0; index < 25; index++ {
		input = append(input, 0xb8, 0x44, 0x33, 0x22, 0x11)
	}
	input = append(input, 0xc3)
	object, text, _ := fixture(t, coff.MachineI386, input)
	report, err := Apply(context.Background(), object, Options{
		Magic:  []uint32{0x20},
		Random: bytes.NewReader(make([]byte, 25*4)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.MutatedInstructions != 25 || len(text.Data) != 256 || !bytes.Equal(text.Data[:5], mustHex(t, "e9fa000000")) || text.Data[255] != 0xc3 {
		t.Fatalf("len=%d prefix=%x suffix=%x report=%#v", len(text.Data), text.Data[:5], text.Data[len(text.Data)-1:], report)
	}
}

func TestApplyRepairsRIPRelativeReference(t *testing.T) {
	object, text, _ := fixture(t, coff.MachineAMD64, mustHex(t, "8b0505000000b844332211c3"))
	target := coff.NewDataSymbol(text, "embedded", 11)
	if err := object.AddSymbol(target); err != nil {
		t.Fatal(err)
	}
	report, err := Apply(context.Background(), object, Options{Magic: []uint32{0x20}, Random: int32Stream(0)})
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "8b050a000000b8243322110520000000c3")
	if !bytes.Equal(text.Data, want) || target.Value != 16 || report.MutatedInstructions != 1 {
		t.Fatalf("data=%x target=%d report=%#v", text.Data, target.Value, report)
	}
}

func TestApplySkipsLiveFlagsZone(t *testing.T) {
	input := mustHex(t, "39d8b9443322117401c3c3")
	object, text, _ := fixture(t, coff.MachineI386, input)
	report, err := Apply(context.Background(), object, Options{Random: bytes.NewReader(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if report != (Report{SkippedDangerous: 1}) || !bytes.Equal(text.Data, input) {
		t.Fatalf("data=%x report=%#v", text.Data, report)
	}
}

func TestApplyDoesNotMutateTextGlobalData(t *testing.T) {
	input := mustHex(t, "b844332211")
	object, err := coff.NewObject(coff.MachineI386)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", input)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(coff.NewDataSymbol(text, "embedded", 0)); err != nil {
		t.Fatal(err)
	}
	report, err := Apply(context.Background(), object, Options{Random: bytes.NewReader(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if report != (Report{}) || !bytes.Equal(text.Data, input) {
		t.Fatalf("data=%x report=%#v", text.Data, report)
	}
}

func TestApplyRandomFailureIsTransactional(t *testing.T) {
	object, text, function := fixture(t, coff.MachineI386, mustHex(t, "b844332211bb88776655c3"))
	before := append([]byte(nil), text.Data...)
	report, err := Apply(context.Background(), object, Options{Magic: []uint32{0x20}, Random: int32Stream(0)})
	if err == nil || !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("report=%#v error=%v", report, err)
	}
	if !bytes.Equal(text.Data, before) || function.Value != 0 {
		t.Fatal("failed pass mutated the COFF object")
	}
}

func TestApplyRejectsSymbolInsideReplacementTransactionally(t *testing.T) {
	object, text, _ := fixture(t, coff.MachineI386, mustHex(t, "b844332211c3"))
	label := &coff.Symbol{Name: "inside", Value: 2, Section: text, StorageClass: coff.SymbolClassLabel}
	if err := object.AddSymbol(label); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), text.Data...)
	if _, err := Apply(context.Background(), object, Options{Magic: []uint32{0x20}, Random: int32Stream(0)}); err == nil {
		t.Fatal("Apply accepted a symbol inside a rewritten instruction")
	}
	if !bytes.Equal(text.Data, before) || label.Value != 2 {
		t.Fatal("rejected pass mutated the model")
	}
}

func TestApplyValidation(t *testing.T) {
	valid, _, _ := fixture(t, coff.MachineI386, mustHex(t, "c3"))
	seed := int64(1)
	tests := []struct {
		name string
		call func() error
	}{
		{name: "nil context", call: func() error { _, err := Apply(nil, valid, Options{}); return err }},
		{name: "nil object", call: func() error { _, err := Apply(context.Background(), nil, Options{}); return err }},
		{name: "random and seed", call: func() error {
			_, err := Apply(context.Background(), valid, Options{Random: bytes.NewReader(nil), Seed: &seed})
			return err
		}},
		{name: "arm64", call: func() error {
			object, _ := coff.NewObject(coff.MachineARM64)
			_ = object.AddSection(coff.NewSection(".text", []byte{0xc0, 0x03, 0x5f, 0xd6}))
			_, err := Apply(context.Background(), object, Options{})
			return err
		}},
		{name: "missing text", call: func() error {
			object, _ := coff.NewObject(coff.MachineI386)
			_, err := Apply(context.Background(), object, Options{})
			return err
		}},
		{name: "text without code symbols", call: func() error {
			object, _ := coff.NewObject(coff.MachineI386)
			_ = object.AddSection(coff.NewSection(".text", []byte{0xc3}))
			_, err := Apply(context.Background(), object, Options{})
			return err
		}},
		{name: "nil symbol", call: func() error {
			object, _, _ := fixture(t, coff.MachineI386, mustHex(t, "c3"))
			object.Symbols = append(object.Symbols, nil)
			_, err := Apply(context.Background(), object, Options{})
			return err
		}},
		{name: "foreign relocation parent", call: func() error {
			object, text, _ := fixture(t, coff.MachineI386, mustHex(t, "b800000000c3"))
			foreign := coff.NewSection(".foreign", nil)
			text.Relocations = []*coff.Relocation{{Section: foreign, VirtualAddress: 1, Type: coff.RelI386Dir32}}
			_, err := Apply(context.Background(), object, Options{})
			return err
		}},
		{name: "noncanonical candidate", call: func() error {
			object, _, _ := fixture(t, coff.MachineI386, mustHex(t, "67b844332211c3"))
			_, err := Apply(context.Background(), object, Options{Random: int32Stream(0)})
			return err
		}},
		{name: "unproven cross-block flags", call: func() error {
			object, _, _ := fixture(t, coff.MachineI386, mustHex(t, "b844332211eb00c3"))
			_, err := Apply(context.Background(), object, Options{Random: int32Stream(0)})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("call succeeded")
			}
		})
	}
}

func TestApplyConcurrentIndependentObjects(t *testing.T) {
	const workers = 4
	want := mustHex(t, "b8243322110520000000c3")
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			object, text, _ := fixture(t, coff.MachineI386, mustHex(t, "b844332211c3"))
			seed := int64(0)
			report, err := Apply(context.Background(), object, Options{Magic: []uint32{0x20}, Seed: &seed})
			if err != nil {
				errorsChannel <- err
				return
			}
			if report.MutatedInstructions != 1 || !bytes.Equal(text.Data, want) {
				errorsChannel <- errors.New("concurrent output mismatch")
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func TestDecodeCandidateForms(t *testing.T) {
	tests := []struct {
		name    string
		machine coff.Machine
		code    string
		kind    candidateKind
	}{
		{name: "cmp eax", machine: coff.MachineI386, code: "3d44332211", kind: candidateCMPRegImm32},
		{name: "cmp r8d", machine: coff.MachineAMD64, code: "4181f844332211", kind: candidateCMPRegImm32},
		{name: "mov esi", machine: coff.MachineI386, code: "be44332211", kind: candidateMOVRegImm32},
		{name: "mov r15d", machine: coff.MachineAMD64, code: "41bf44332211", kind: candidateMOVRegImm32},
		{name: "mov rax", machine: coff.MachineAMD64, code: "48b88877665544332211", kind: candidateMOVRegImm64},
		{name: "mov ebp memory", machine: coff.MachineI386, code: "c7450078563412", kind: candidateMOVStackImm32},
		{name: "mov rsp memory", machine: coff.MachineAMD64, code: "c7042478563412", kind: candidateMOVStackImm32},
		{name: "push", machine: coff.MachineI386, code: "6844332211", kind: candidatePUSHImm32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate, ok, err := decodeCandidate(mustHex(t, test.code), test.machine)
			if err != nil || !ok || candidate.kind != test.kind {
				t.Fatalf("candidate=%#v ok=%v err=%v", candidate, ok, err)
			}
		})
	}
}

func FuzzDecodeCandidate(f *testing.F) {
	for _, seed := range []struct {
		code string
		x64  bool
	}{
		{code: "b844332211", x64: false},
		{code: "49b88877665544332211", x64: true},
		{code: "c744242078563412", x64: true},
		{code: "0f", x64: false},
	} {
		f.Add(mustHex(f, seed.code), seed.x64)
	}
	f.Fuzz(func(t *testing.T, raw []byte, useX64 bool) {
		machine := coff.MachineI386
		if useX64 {
			machine = coff.MachineAMD64
		}
		candidate, ok, _ := decodeCandidate(raw, machine)
		if !ok {
			return
		}
		_, _, _ = candidate.encode(readerRandom{reader: bytes.NewReader(make([]byte, 8))}, []uint32{0x20}, machine)
		_, _ = ripDisplacementOffset(raw)
	})
}

func FuzzRelativeWalkers(f *testing.F) {
	for _, seed := range [][]byte{
		mustHex(f, "eb7f"),
		mustHex(f, "0f8400000000"),
		mustHex(f, "8b0500000000"),
		{0x0f},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = decodeRelative(raw)
		_, _ = ripDisplacementOffset(raw)
	})
}

func fixture(t testing.TB, machine coff.Machine, code []byte) (*coff.Object, *coff.Section, *coff.Symbol) {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", code)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	function := coff.NewFunctionSymbol(text, "go", 0)
	if err := object.AddSymbol(function); err != nil {
		t.Fatal(err)
	}
	return object, text, function
}

func int32Stream(values ...int32) io.Reader {
	data := make([]byte, len(values)*4)
	for index, value := range values {
		binary.BigEndian.PutUint32(data[index*4:], uint32(value))
	}
	return bytes.NewReader(data)
}

type fataler interface {
	Helper()
	Fatalf(string, ...any)
}

func mustHex(t fataler, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

func assertDisassembles(t testing.TB, mode x86.Mode, code []byte) {
	t.Helper()
	decoder, err := x86.NewCapstone(context.Background(), mode)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close(context.Background())
	if _, err := decoder.Disassemble(context.Background(), code, 0); err != nil {
		t.Fatalf("rewritten bytes do not disassemble: %v\n%x", err, code)
	}
}

func TestFailedPassPreservesRelocationPointers(t *testing.T) {
	object, text, _ := fixture(t, coff.MachineI386, mustHex(t, "b844332211bb00000000c3"))
	data := coff.NewSection(".data", make([]byte, 4))
	if err := object.AddSection(data); err != nil {
		t.Fatal(err)
	}
	symbol := coff.NewDataSymbol(data, "target", 0)
	if err := object.AddSymbol(symbol); err != nil {
		t.Fatal(err)
	}
	relocation := &coff.Relocation{Section: text, VirtualAddress: 6, SymbolName: symbol.Name, Symbol: symbol, Type: coff.RelI386Dir32}
	text.Relocations = []*coff.Relocation{relocation}
	beforeRelocations := append([]*coff.Relocation(nil), text.Relocations...)
	beforeData := append([]byte(nil), text.Data...)
	_, err := Apply(context.Background(), object, Options{Magic: []uint32{0x20}, Random: bytes.NewReader(nil)})
	if err == nil {
		t.Fatal("Apply unexpectedly succeeded")
	}
	if !bytes.Equal(text.Data, beforeData) || !reflect.DeepEqual(text.Relocations, beforeRelocations) || text.Relocations[0] != relocation || relocation.VirtualAddress != 6 {
		t.Fatal("failed pass changed relocation graph")
	}
}
