// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package unwindgen

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var (
	sharedDecoder     *x86.Capstone
	sharedDecoderErr  error
	sharedDecoderOnce sync.Once
)

func TestMain(m *testing.M) {
	status := m.Run()
	if sharedDecoder != nil {
		if err := sharedDecoder.Close(context.Background()); err != nil && status == 0 {
			fmt.Fprintln(os.Stderr, err)
			status = 1
		}
	}
	os.Exit(status)
}

func decoderOptions() Options {
	sharedDecoderOnce.Do(func() {
		sharedDecoder, sharedDecoderErr = x86.NewCapstone(context.Background(), x86.Mode64)
	})
	if sharedDecoderErr != nil {
		panic(sharedDecoderErr)
	}
	return Options{Disassembler: sharedDecoder}
}

func TestGenerateExactUpstreamVector(t *testing.T) {
	code := []byte{
		0x55,                   // push rbp
		0x53,                   // push rbx
		0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0xe8, 0x00, 0x00, 0x00, 0x00, // call next
		0x48, 0x83, 0xc4, 0x20, // add rsp, 0x20
		0x5b, 0x5d, 0xc3, // pop rbx; pop rbp; ret
	}
	object, _ := unwindObject(t, code, map[string]uint32{"work": 0})
	result, err := Generate(context.Background(), object, hooks.Snapshot{Machine: "x64"}, decoderOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	wantPDATA := make([]byte, 12)
	binary.LittleEndian.PutUint32(wantPDATA[4:8], uint32(len(code)))
	wantXDATA := []byte{
		0x01, 0x09, 0x04, 0x05,
		0x09, 0x03,
		0x06, 0x32,
		0x02, 0x30,
		0x01, 0x50,
	}
	if !bytes.Equal(result.PDATA.Data, wantPDATA) {
		t.Fatalf("pdata = %x, want %x", result.PDATA.Data, wantPDATA)
	}
	if !bytes.Equal(result.XDATA.Data, wantXDATA) {
		t.Fatalf("xdata = %x, want %x", result.XDATA.Data, wantXDATA)
	}
	if result.PDATA.Alignment != 4 || result.XDATA.Alignment != 4 {
		t.Fatalf("alignments = %d,%d", result.PDATA.Alignment, result.XDATA.Alignment)
	}
	if len(result.PDATA.Relocations) != 3 {
		t.Fatalf("pdata relocations = %#v", result.PDATA.Relocations)
	}
	for index, relocation := range result.PDATA.Relocations {
		if relocation.VirtualAddress != uint32(index*4) || relocation.Type != coff.RelAMD64Addr32NB || relocation.Section != result.PDATA {
			t.Fatalf("relocation[%d] = %#v", index, relocation)
		}
	}
	if result.PDATA.Relocations[0].SymbolName != ".text" || result.PDATA.Relocations[1].SymbolName != ".text" || result.PDATA.Relocations[2].SymbolName != ".xdata" {
		t.Fatalf("relocation names = %q,%q,%q", result.PDATA.Relocations[0].SymbolName, result.PDATA.Relocations[1].SymbolName, result.PDATA.Relocations[2].SymbolName)
	}
	if got, want := fmt.Sprint(result.Functions), "[{work 0 21 0 }]"; got != want {
		t.Fatalf("Functions = %s, want %s", got, want)
	}
	if len(result.SkippedLeaves) != 0 {
		t.Fatalf("SkippedLeaves = %v", result.SkippedLeaves)
	}
	if findSection(object, ".pdata") != nil || findSection(object, ".xdata") != nil {
		t.Fatal("Generate mutated the object")
	}

	clone := result.Clone()
	clone.PDATA.Data[0] = 0xff
	clone.XDATA.Relocations = append(clone.XDATA.Relocations, nil)
	clone.Functions[0].Name = "changed"
	if result.PDATA.Data[0] != 0 || len(result.XDATA.Relocations) != 0 || result.Functions[0].Name != "work" {
		t.Fatal("Result.Clone aliases generated state")
	}
}

func TestGenerateLeafCallAndFunctionBoundaries(t *testing.T) {
	code := []byte{
		0xc3,                               // leaf at 0
		0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3, // caller at 1
		0x90, 0x90, // global code-data label at 7
		0x55, 0xc3, // framed at 9
	}
	object, text := unwindObject(t, code, map[string]uint32{"leaf": 0, "caller": 1, "framed": 9})
	if err := object.AddSymbol(coff.NewDataSymbol(text, "literal", 7)); err != nil {
		t.Fatal(err)
	}
	result, err := Generate(context.Background(), object, hooks.Snapshot{}, decoderOptions())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got, want := fmt.Sprint(result.SkippedLeaves), "[leaf]"; got != want {
		t.Fatalf("SkippedLeaves = %s, want %s", got, want)
	}
	if len(result.Functions) != 2 || result.Functions[0].Name != "caller" || result.Functions[0].EndAddress != 7 || result.Functions[1].Name != "framed" || result.Functions[1].EndAddress != uint32(len(code)) {
		t.Fatalf("Functions = %#v", result.Functions)
	}
	if len(result.PDATA.Data) != 24 {
		t.Fatalf("pdata length = %d", len(result.PDATA.Data))
	}
	if result.Functions[1].UnwindOffset != 4 {
		t.Fatalf("framed unwind offset = %d", result.Functions[1].UnwindOffset)
	}
}

func TestCatchIntegrationAndParsedMetadata(t *testing.T) {
	code := make([]byte, 24)
	for index := range code {
		code[index] = 0x90
	}
	copy(code, []byte{0x55, 0xe8, 0, 0, 0, 0, 0x5d, 0xc3})
	code[16] = 0xc3
	object, _ := unwindObject(t, code, map[string]uint32{"caught": 0, "handler": 16})
	snapshot := hooks.Snapshot{Machine: "x64", Catches: []hooks.CatchSnapshot{{Function: "caught", Handler: "handler"}}}
	result, err := Apply(context.Background(), object, snapshot, decoderOptions())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(result.Functions) != 1 || result.Functions[0].Handler != "handler" {
		t.Fatalf("Functions = %#v", result.Functions)
	}
	if got, want := result.XDATA.Data, []byte{0x09, 0x01, 0x01, 0x00, 0x01, 0x50, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("xdata = %x, want %x", got, want)
	}
	if len(result.XDATA.Relocations) != 1 {
		t.Fatalf("xdata relocations = %#v", result.XDATA.Relocations)
	}
	relocation := result.XDATA.Relocations[0]
	if relocation.VirtualAddress != 8 || relocation.SymbolName != ".text" || relocation.Symbol == nil || relocation.Symbol.Section != findSection(object, ".text") {
		t.Fatalf("handler relocation = %#v", relocation)
	}
	rows, err := coff.ParsePDATA(object)
	if err != nil {
		t.Fatalf("ParsePDATA: %v", err)
	}
	if len(rows) != 1 || rows[0].Function != "caught" || rows[0].Unwind == nil || rows[0].Unwind.Flags != coff.UnwindFlagEHandler || rows[0].Unwind.ExceptionHandler == nil || *rows[0].Unwind.ExceptionHandler != 16 {
		t.Fatalf("rows = %#v", rows)
	}
	if len(rows[0].Unwind.Codes) != 1 || rows[0].Unwind.Codes[0].Operation != coff.UnwindOpPushNonVol {
		t.Fatalf("unwind codes = %#v", rows[0].Unwind.Codes)
	}
}

func TestUnwindAllocationVectors(t *testing.T) {
	tests := []struct {
		name   string
		amount uint32
		want   []byte
		slots  int
	}{
		{name: "small minimum", amount: 8, want: []byte{1, 4, 1, 0, 4, 2}, slots: 1},
		{name: "small maximum", amount: 128, want: []byte{1, 4, 1, 0, 4, 0xf2}, slots: 1},
		{name: "large scaled", amount: 136, want: []byte{1, 4, 2, 0, 4, 1, 17, 0}, slots: 2},
		{name: "large scaled maximum", amount: 524280, want: []byte{1, 4, 2, 0, 4, 1, 0xff, 0xff}, slots: 2},
		{name: "large unscaled", amount: 524288, want: []byte{1, 4, 3, 0, 4, 0x11, 0, 0, 8, 0}, slots: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction := x86.Instruction{Address: 0, Bytes: []byte{0x48, 0x83, 0xec, 0x20}, Mnemonic: "sub", Operands: "rsp, 0x20"}
			function := analyzedFunction{
				name: "f", start: 0, prologue: []int{0},
				instructions: []instructionDetail{{instruction: instruction, kind: kindSubRSP, amount: test.amount}},
			}
			got, slots, err := encodeUnwindInfo(function, false)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, test.want) || slots != test.slots {
				t.Fatalf("encode = %x,%d want %x,%d", got, slots, test.want, test.slots)
			}
		})
	}

	volatile := analyzedFunction{
		name: "v", prologue: []int{0},
		instructions: []instructionDetail{{instruction: x86.Instruction{Bytes: []byte{0x50}, Mnemonic: "push", Operands: "rax"}, kind: kindPush, register: 0}},
	}
	if got, slots, err := encodeUnwindInfo(volatile, true); err != nil || slots != 1 || !bytes.Equal(got, []byte{9, 1, 1, 0, 1, 2}) {
		t.Fatalf("volatile push = %x,%d,%v", got, slots, err)
	}
}

func TestLEAFramePointerVector(t *testing.T) {
	code := []byte{0x48, 0x83, 0xec, 0x20, 0x48, 0x8d, 0x6c, 0x24, 0x20, 0xc3}
	object, _ := unwindObject(t, code, map[string]uint32{"frame": 0})
	result, err := Generate(context.Background(), object, hooks.Snapshot{}, decoderOptions())
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 9, 2, 0x25, 9, 3, 4, 0x32}
	if !bytes.Equal(result.XDATA.Data, want) {
		t.Fatalf("xdata = %x, want %x", result.XDATA.Data, want)
	}
}

func TestDynamicAndUnsupportedValidation(t *testing.T) {
	t.Run("exact dynamic frame advice", func(t *testing.T) {
		code := []byte{0x90, 0x48, 0x83, 0xec, 0x20, 0xc3}
		object, _ := unwindObject(t, code, map[string]uint32{"dynamic": 0})
		_, err := Generate(context.Background(), object, hooks.Snapshot{}, decoderOptions())
		want := "I can't generate +unwind for dynamic. Stack frame is dynamic. I need a frame pointer. Recompile module with -fno-omit-frame-pointer or decorate function with __attribute__((optimize(\"no-omit-frame-pointer\")))"
		if err == nil || !errors.Is(err, ErrDynamicFrame) || err.Error() != want {
			t.Fatalf("error = %v, want %q", err, want)
		}
	})

	tests := []struct {
		name string
		code []byte
	}{
		{name: "memory push", code: []byte{0xff, 0x30, 0xc3}},
		{name: "operand-size push", code: []byte{0x66, 0x55, 0xc3}},
		{name: "unencodable allocation", code: []byte{0x48, 0x83, 0xec, 0x07, 0xc3}},
		{name: "unencodable frame offset", code: []byte{0x48, 0x8d, 0x6c, 0x24, 0x08, 0xc3}},
		{name: "bare secondary stack pointer", code: []byte{0x48, 0x39, 0xe0, 0xc3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object, _ := unwindObject(t, test.code, map[string]uint32{"bad": 0})
			_, err := Generate(context.Background(), object, hooks.Snapshot{}, decoderOptions())
			if err == nil || !errors.Is(err, ErrUnsupportedDetail) {
				t.Fatalf("error = %v", err)
			}
			var unsupported *UnsupportedError
			if !errors.As(err, &unsupported) || unsupported.Function != "bad" {
				t.Fatalf("error type = %T %#v", err, unsupported)
			}
		})
	}

	x86Object, err := coff.NewObject(coff.MachineI386)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(context.Background(), x86Object, hooks.Snapshot{}, Options{}); !errors.Is(err, ErrUnsupportedDetail) {
		t.Fatalf("x86 error = %v", err)
	}
}

func TestResourceConstructionAndExportOrder(t *testing.T) {
	code := []byte{0x55, 0xc3}
	object, _ := unwindObject(t, code, map[string]uint32{"work": 0})
	result, err := Apply(context.Background(), object, hooks.Snapshot{}, decoderOptions())
	if err != nil {
		t.Fatal(err)
	}
	resource, err := BuildResource(".cpl_unwind", result)
	if err != nil {
		t.Fatalf("BuildResource: %v", err)
	}
	if resource.Alignment != 4 || len(resource.Data) != 28 {
		t.Fatalf("resource alignment/length = %d/%d data=%x", resource.Alignment, len(resource.Data), resource.Data)
	}
	if got := binary.LittleEndian.Uint32(resource.Data[0:4]); got != 12 {
		t.Fatalf("pdata length header = %d", got)
	}
	if got := binary.LittleEndian.Uint32(resource.Data[12:16]); got != 20 {
		t.Fatalf("rebased UnwindData = %d, want 20", got)
	}
	if got := binary.LittleEndian.Uint32(resource.Data[16:20]); got != 8 {
		t.Fatalf("xdata length header = %d", got)
	}
	if binary.LittleEndian.Uint32(result.PDATA.Data[8:12]) != 0 {
		t.Fatal("BuildResource mutated generated pdata")
	}
	if len(resource.Relocations) != 3 || resource.Relocations[2].VirtualAddress != 12 || resource.Relocations[2].SymbolName != ".cpl_unwind" || resource.Relocations[2].Symbol != nil {
		t.Fatalf("resource relocations = %#v", resource.Relocations)
	}
	installed, err := InstallResource(object, resource)
	if err != nil {
		t.Fatalf("InstallResource: %v", err)
	}
	if installed != findSection(object, ".cpl_unwind") || installed.Object != object || installed.Relocations[2].Symbol == nil || installed.Relocations[2].Symbol.Section != installed {
		t.Fatalf("installed resource invariants failed: %#v", installed)
	}
	wantOrder := []ExportPhase{PhaseTransform, PhaseGenerateUnwind, PhaseDiagnostics, PhasePatches, PhaseLinkPostResources, PhasePICOResource, PhaseFinalExport}
	gotOrder := ExportOrder()
	if fmt.Sprint(gotOrder) != fmt.Sprint(wantOrder) {
		t.Fatalf("ExportOrder = %v, want %v", gotOrder, wantOrder)
	}
	gotOrder[0] = "changed"
	if ExportOrder()[0] != PhaseTransform {
		t.Fatal("ExportOrder exposed mutable storage")
	}
	if linkpost, err := BuildResource("user_unwind", result); err != nil || linkpost.Name != "user_unwind" {
		t.Fatalf("linkpost resource = %#v, %v", linkpost, err)
	}

	badAlignment := result.Clone()
	badAlignment.PDATA.Alignment = 8
	if _, err := BuildResource("bad", badAlignment); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad alignment error = %v", err)
	}
	badParent := result.Clone()
	badParent.PDATA.Relocations[0].Section = badParent.XDATA
	if _, err := BuildResource("bad", badParent); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad relocation parent error = %v", err)
	}
	badLength := result.Clone()
	badLength.PDATA.Data = badLength.PDATA.Data[:11]
	if _, err := BuildResource("bad", badLength); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad pdata length error = %v", err)
	}
}

func TestApplyReplacesStaleSectionsAndIsTransactional(t *testing.T) {
	code := []byte{0x55, 0xc3}
	object, _ := unwindObject(t, code, map[string]uint32{"work": 0})
	oldPData := coff.NewSection(".pdata", []byte{0xaa})
	oldXData := coff.NewSection(".xdata", []byte{0xbb})
	if err := object.AddSection(oldPData); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSection(oldXData); err != nil {
		t.Fatal(err)
	}
	result, err := Apply(context.Background(), object, hooks.Snapshot{}, decoderOptions())
	if err != nil {
		t.Fatal(err)
	}
	if result.PDATA == oldPData || result.XDATA == oldXData || bytes.Equal(result.PDATA.Data, oldPData.Data) {
		t.Fatal("stale sections were not replaced")
	}
	for _, section := range object.Sections {
		if section.Object != object {
			t.Fatalf("section %s object = %p, want %p", section.Name, section.Object, object)
		}
		for _, relocation := range section.Relocations {
			if relocation.Section != section {
				t.Fatalf("section %s relocation parent mismatch", section.Name)
			}
		}
	}
	firstPData, firstXData := append([]byte(nil), result.PDATA.Data...), append([]byte(nil), result.XDATA.Data...)
	result, err = Apply(context.Background(), object, hooks.Snapshot{}, decoderOptions())
	if err != nil || !bytes.Equal(result.PDATA.Data, firstPData) || !bytes.Equal(result.XDATA.Data, firstXData) {
		t.Fatalf("second Apply = %x/%x, %v", result.PDATA.Data, result.XDATA.Data, err)
	}

	conflict, _ := unwindObject(t, code, map[string]uint32{"work": 0})
	if err := conflict.AddSymbol(&coff.Symbol{Name: ".pdata", StorageClass: coff.SymbolClassExternal}); err != nil {
		t.Fatal(err)
	}
	sectionsBefore := append([]*coff.Section(nil), conflict.Sections...)
	symbolsBefore := append([]*coff.Symbol(nil), conflict.Symbols...)
	_, err = Apply(context.Background(), conflict, hooks.Snapshot{}, decoderOptions())
	if err == nil {
		t.Fatal("Apply with conflicting .pdata symbol succeeded")
	}
	if len(conflict.Sections) != len(sectionsBefore) || len(conflict.Symbols) != len(symbolsBefore) {
		t.Fatal("failed Apply mutated object lengths")
	}
	for index := range sectionsBefore {
		if conflict.Sections[index] != sectionsBefore[index] {
			t.Fatal("failed Apply replaced an original section")
		}
	}
	for index := range symbolsBefore {
		if conflict.Symbols[index] != symbolsBefore[index] {
			t.Fatal("failed Apply replaced an original symbol")
		}
	}
}

func TestCatchAndMalformedInputValidation(t *testing.T) {
	code := []byte{0x55, 0xc3}
	object, _ := unwindObject(t, code, map[string]uint32{"work": 0})
	originalText := findSection(object, ".text")
	_, err := Apply(context.Background(), object, hooks.Snapshot{Machine: "x64", Catches: []hooks.CatchSnapshot{{Function: "work", Handler: "missing"}}}, decoderOptions())
	if err == nil || err.Error() != "unwindgen: catch validation in work: No symbol missing in object" {
		t.Fatalf("missing handler error = %v", err)
	}
	if findSection(object, ".text") != originalText {
		t.Fatal("failed catch Apply mutated object")
	}

	if _, err := Generate(nil, object, hooks.Snapshot{}, Options{}); !errors.Is(err, x86.ErrNilContext) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := Generate(context.Background(), nil, hooks.Snapshot{}, Options{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil object error = %v", err)
	}
	truncated, _ := unwindObject(t, []byte{0x48, 0x83}, map[string]uint32{"bad": 0})
	if _, err := Generate(context.Background(), truncated, hooks.Snapshot{}, decoderOptions()); err == nil {
		t.Fatal("truncated instruction unexpectedly generated")
	} else {
		var generationError *Error
		if !errors.As(err, &generationError) || generationError.Stage != "disassembly" {
			t.Fatalf("truncation error = %T %v", err, err)
		}
	}
	misaligned, text := unwindObject(t, []byte{0xe8, 0, 0, 0, 0, 0xc3}, map[string]uint32{"caller": 0})
	if err := misaligned.AddSymbol(coff.NewDataSymbol(text, "inside_call", 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(context.Background(), misaligned, hooks.Snapshot{}, decoderOptions()); err == nil || !strings.Contains(err.Error(), "code label is not on an instruction boundary") {
		t.Fatalf("misaligned code label error = %v", err)
	}
	if _, err := BuildResource("", Result{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty resource error = %v", err)
	}
}

func TestCancellationFactoryLifecycleAndConcurrentUse(t *testing.T) {
	object, _ := unwindObject(t, []byte{0x55, 0xc3}, map[string]uint32{"work": 0})
	ctx, cancel := context.WithCancel(context.Background())
	decoder := &testDecoder{decode: func(ctx context.Context, _ []byte, _ uint64) ([]x86.Instruction, error) {
		cancel()
		return nil, ctx.Err()
	}}
	if _, err := Generate(ctx, object, hooks.Snapshot{}, Options{Disassembler: decoder}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if decoder.closed != 0 {
		t.Fatalf("caller-owned decoder closed %d times", decoder.closed)
	}

	factoryDecoder := fixedInstructions([]x86.Instruction{{Address: 0, Bytes: []byte{0x55}, Mnemonic: "push", Operands: "rbp"}, {Address: 1, Bytes: []byte{0xc3}, Mnemonic: "ret"}})
	if _, err := Generate(context.Background(), object, hooks.Snapshot{}, Options{Factory: func(_ context.Context, mode x86.Mode) (x86.Disassembler, error) {
		if mode != x86.Mode64 {
			t.Fatalf("factory mode = %v", mode)
		}
		return factoryDecoder, nil
	}}); err != nil {
		t.Fatalf("factory Generate: %v", err)
	}
	if factoryDecoder.closed != 1 {
		t.Fatalf("factory decoder closed %d times", factoryDecoder.closed)
	}
	if _, err := Generate(context.Background(), object, hooks.Snapshot{}, Options{Disassembler: factoryDecoder, Factory: func(context.Context, x86.Mode) (x86.Disassembler, error) { return factoryDecoder, nil }}); err == nil {
		t.Fatal("both decoder options succeeded")
	}

	const workers = 16
	var wait sync.WaitGroup
	errorsOut := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 10; iteration++ {
				result, err := Generate(context.Background(), object, hooks.Snapshot{}, decoderOptions())
				if err != nil {
					errorsOut <- err
					return
				}
				if _, err := BuildResource("resource", result); err != nil {
					errorsOut <- err
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsOut)
	for err := range errorsOut {
		t.Fatal(err)
	}
}

type testDecoder struct {
	decode func(context.Context, []byte, uint64) ([]x86.Instruction, error)
	closed int
}

func (d *testDecoder) Disassemble(ctx context.Context, code []byte, address uint64) ([]x86.Instruction, error) {
	return d.decode(ctx, code, address)
}

func (d *testDecoder) Close(context.Context) error {
	d.closed++
	return nil
}

func fixedInstructions(instructions []x86.Instruction) *testDecoder {
	return &testDecoder{decode: func(context.Context, []byte, uint64) ([]x86.Instruction, error) {
		result := make([]x86.Instruction, len(instructions))
		copy(result, instructions)
		return result, nil
	}}
}

func unwindObject(t *testing.T, code []byte, functions map[string]uint32) (*coff.Object, *coff.Section) {
	t.Helper()
	object, err := coff.NewObject(coff.MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", code)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	for name, offset := range functions {
		if err := object.AddSymbol(coff.NewFunctionSymbol(text, name, offset)); err != nil {
			t.Fatal(err)
		}
	}
	return object, text
}

func findSection(object *coff.Object, name string) *coff.Section {
	if object == nil {
		return nil
	}
	for _, section := range object.Sections {
		if section != nil && section.Name == name {
			return section
		}
	}
	return nil
}
