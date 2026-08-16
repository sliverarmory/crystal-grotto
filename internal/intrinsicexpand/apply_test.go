// SPDX-License-Identifier: GPL-3.0-only

package intrinsicexpand

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/hookencode"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
	"github.com/sliverarmory/crystal-grotto/internal/ised"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestApplyLengthChangingUserIntrinsicX64AndX86(t *testing.T) {
	for _, test := range []struct {
		name        string
		machine     coff.Machine
		symbol      string
		relocation  uint16
		replacement []byte
		want        []byte
	}{
		{
			name: "x64 grow", machine: coff.MachineAMD64, symbol: "__custom", relocation: coff.RelAMD64Rel32,
			replacement: []byte{0xb8, 0x2a, 0, 0, 0, 0x90}, want: []byte{0xb8, 0x2a, 0, 0, 0, 0x90, 0x90, 0xc3},
		},
		{
			name: "x86 shrink", machine: coff.MachineI386, symbol: "___custom", relocation: coff.RelI386Rel32,
			replacement: []byte{0x90}, want: []byte{0x90, 0x90, 0xc3},
		},
		{
			name: "x64 delete", machine: coff.MachineAMD64, symbol: "__custom", relocation: coff.RelAMD64Rel32,
			replacement: nil, want: []byte{0x90, 0xc3},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			object, text, model := fixture(t, test.machine, []byte{0xe8, 0, 0, 0, 0, 0x90, 0xc3}, test.symbol, test.relocation, test.replacement)
			before := append([]byte(nil), text.Data...)
			result, report, err := Apply(context.Background(), object, model, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(result.GetSection(".text").Data, test.want) {
				t.Fatalf("output = %x, want %x", result.GetSection(".text").Data, test.want)
			}
			if len(result.GetSection(".text").Relocations) != 0 {
				t.Fatalf("intrinsic relocation remains: %#v", result.GetSection(".text").Relocations)
			}
			if len(report.Sites) != 1 || report.Sites[0].Function != entryName(test.machine) || report.Sites[0].Symbol != test.symbol || report.Sites[0].Offset != 0 || report.BytesDelta != int64(len(test.replacement)-5) {
				t.Fatalf("report = %#v", report)
			}
			if !bytes.Equal(text.Data, before) || len(text.Relocations) != 1 {
				t.Fatal("Apply mutated its source")
			}
		})
	}
}

func TestApplyAcceptsIcedCallRel32WithRedundantPrefix(t *testing.T) {
	object, text, model := fixture(t, coff.MachineAMD64,
		[]byte{0x2e, 0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
	text.Relocations[0].VirtualAddress = 2
	result, report, err := Apply(context.Background(), object, model, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.GetSection(".text").Data, []byte{0x90, 0xc3}) || len(report.Sites) != 1 || report.Sites[0].OriginalLen != 6 || report.BytesDelta != -5 {
		t.Fatalf("result/report = %x / %#v", result.GetSection(".text").Data, report)
	}
}

type fixedCallDecoder struct{}

func (fixedCallDecoder) Disassemble(ctx context.Context, code []byte, address uint64) ([]x86.Instruction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if address != 0 || !bytes.Equal(code, []byte{0xe8, 0, 0, 0, 0, 0xc3}) {
		return nil, errors.New("fixedCallDecoder received unexpected input")
	}
	return []x86.Instruction{
		{Address: 0, Bytes: append([]byte(nil), code[:5]...), Mnemonic: "call", Operands: "5"},
		{Address: 5, Bytes: append([]byte(nil), code[5:]...), Mnemonic: "ret"},
	}, nil
}

func (fixedCallDecoder) Close(context.Context) error { return nil }

type linearDecoder struct {
	closeCalls *atomic.Int32
	decodeErr  error
	closeErr   error
}

func (decoder linearDecoder) Disassemble(ctx context.Context, code []byte, address uint64) ([]x86.Instruction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if decoder.decodeErr != nil {
		return nil, decoder.decodeErr
	}
	result := make([]x86.Instruction, 0, len(code))
	for offset := 0; offset < len(code); {
		length := 1
		mnemonic := ""
		switch code[offset] {
		case 0xe8:
			length, mnemonic = 5, "call"
		case 0xeb:
			length, mnemonic = 2, "jmp"
		case 0x90:
			mnemonic = "nop"
		case 0xcc:
			mnemonic = "int3"
		case 0xc3:
			mnemonic = "ret"
		default:
			return nil, fmt.Errorf("linearDecoder: unsupported opcode %#x at %d", code[offset], offset)
		}
		if length > len(code)-offset {
			return nil, errors.New("linearDecoder: truncated instruction")
		}
		result = append(result, x86.Instruction{
			Address: address + uint64(offset), Bytes: append([]byte(nil), code[offset:offset+length]...), Mnemonic: mnemonic,
		})
		offset += length
	}
	return result, nil
}

func (decoder linearDecoder) Close(context.Context) error {
	if decoder.closeCalls != nil {
		decoder.closeCalls.Add(1)
	}
	return decoder.closeErr
}

func TestApplyRepairsCrossingBranchAndSymbol(t *testing.T) {
	object, text, model := fixture(t, coff.MachineAMD64,
		[]byte{0xeb, 0x05, 0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
	text.Relocations[0].VirtualAddress = 3
	helper := coff.NewFunctionSymbol(text, "helper", 7)
	if err := object.AddSymbol(helper); err != nil {
		t.Fatal(err)
	}
	result, _, err := Apply(context.Background(), object, model, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xeb, 0x01, 0x90, 0xc3}; !bytes.Equal(result.GetSection(".text").Data, want) {
		t.Fatalf("rebuilt text = %x, want %x", result.GetSection(".text").Data, want)
	}
	if moved := result.GetSymbol("helper"); moved == nil || moved.Value != 3 {
		t.Fatalf("helper = %#v, want offset 3", moved)
	}
}

func TestApplyRejectsBranchThatRequiresRelaxation(t *testing.T) {
	code := make([]byte, 129)
	code[0], code[1] = 0xeb, 0x7e // Jump from 0 to the RET at 128.
	code[2] = 0xe8
	for index := 7; index < 128; index++ {
		code[index] = 0x90
	}
	code[128] = 0xc3
	object, text, model := fixture(t, coff.MachineAMD64, code, "__custom", coff.RelAMD64Rel32, bytes.Repeat([]byte{0x90}, 10))
	text.Relocations[0].VirtualAddress = 3
	before := append([]byte(nil), text.Data...)
	result, _, err := Apply(context.Background(), object, model, Options{Disassembler: linearDecoder{}})
	if result != nil || !errors.Is(err, ised.ErrBranchOutOfRange) {
		t.Fatalf("result/error = %#v / %v", result, err)
	}
	if !bytes.Equal(text.Data, before) || len(text.Relocations) != 1 {
		t.Fatal("branch-range rejection mutated source")
	}
}

func TestApplyMultipleSitesAndRemainingRelocation(t *testing.T) {
	object, err := coff.NewObject(coff.MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", []byte{
		0xe8, 0, 0, 0, 0,
		0xe8, 0, 0, 0, 0,
		0xe8, 0, 0, 0, 0,
		0xc3,
	})
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	for _, symbol := range []*coff.Symbol{
		coff.NewFunctionSymbol(text, "go", 0),
		{Name: "__first", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal},
		{Name: "external", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal},
		{Name: "__second", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal},
	} {
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
	}
	// Deliberately keep relocation order different from site order.
	text.Relocations = []*coff.Relocation{
		{Section: text, VirtualAddress: 11, Symbol: object.GetSymbol("__second"), SymbolName: "__second", Type: coff.RelAMD64Rel32},
		{Section: text, VirtualAddress: 6, Symbol: object.GetSymbol("external"), SymbolName: "external", Type: coff.RelAMD64Rel32},
		{Section: text, VirtualAddress: 1, Symbol: object.GetSymbol("__first"), SymbolName: "__first", Type: coff.RelAMD64Rel32},
	}
	model, err := hooks.New(object)
	if err != nil {
		t.Fatal(err)
	}
	model = addUserIntrinsic(t, model, object, "__first", []byte{0x90})
	model = addUserIntrinsic(t, model, object, "__second", []byte{0x90, 0xcc, 0x90, 0xcc, 0x90, 0xcc})

	before := append([]byte(nil), text.Data...)
	result, report, err := Apply(context.Background(), object, model, Options{Disassembler: linearDecoder{}})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x90, 0xe8, 0, 0, 0, 0, 0x90, 0xcc, 0x90, 0xcc, 0x90, 0xcc, 0xc3}
	if !bytes.Equal(result.GetSection(".text").Data, want) {
		t.Fatalf("output = %x, want %x", result.GetSection(".text").Data, want)
	}
	relocations := result.GetSection(".text").Relocations
	if len(relocations) != 1 || relocations[0].SymbolName != "external" || relocations[0].VirtualAddress != 2 {
		t.Fatalf("remaining relocations = %#v", relocations)
	}
	if len(report.Sites) != 2 || report.Sites[0].Offset != 0 || report.Sites[1].Offset != 10 || report.BytesDelta != -3 {
		t.Fatalf("report = %#v", report)
	}
	if result.GetSymbol("__first") != nil || result.GetSymbol("__second") != nil || result.GetSymbol("external") == nil {
		t.Fatalf("post-expansion symbols are wrong: first=%#v second=%#v external=%#v", result.GetSymbol("__first"), result.GetSymbol("__second"), result.GetSymbol("external"))
	}
	if !bytes.Equal(text.Data, before) || len(text.Relocations) != 3 {
		t.Fatal("multi-site Apply mutated source")
	}
}

func TestApplyRepairsFunctionAuxiliarySize(t *testing.T) {
	object, _, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
	function := object.GetSymbol("go")
	function.AuxiliaryRecords = [][]byte{make([]byte, 18)}
	binary.LittleEndian.PutUint32(function.AuxiliaryRecords[0][4:8], 6)

	result, _, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(result.GetSymbol("go").AuxiliaryRecords[0][4:8]); got != 2 {
		t.Fatalf("rebased function size = %d, want 2", got)
	}
	if got := binary.LittleEndian.Uint32(function.AuxiliaryRecords[0][4:8]); got != 6 {
		t.Fatalf("source function size changed to %d", got)
	}
}

func TestApplyRepairsCrossSectionAddend(t *testing.T) {
	object, _, model := fixture(t, coff.MachineI386, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "___custom", coff.RelI386Rel32, []byte{0x90})
	rdata := coff.NewSection(".rdata", make([]byte, 4))
	binary.LittleEndian.PutUint32(rdata.Data, 6)
	if err := object.AddSection(rdata); err != nil {
		t.Fatal(err)
	}
	textSymbol := object.GetSymbol(".text")
	rdata.Relocations = []*coff.Relocation{{
		Section: rdata, VirtualAddress: 0, Symbol: textSymbol, SymbolName: textSymbol.Name, Type: coff.RelI386Dir32,
	}}

	result, _, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(result.GetSection(".rdata").Data); got != 2 {
		t.Fatalf("rebased .text addend = %d, want 2", got)
	}
	if got := binary.LittleEndian.Uint32(rdata.Data); got != 6 {
		t.Fatalf("source addend changed to %d", got)
	}
}

func TestApplyRepairsRelocationBackedPdataRange(t *testing.T) {
	object, _, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
	pdata := coff.NewSection(".pdata", make([]byte, 12))
	binary.LittleEndian.PutUint32(pdata.Data[4:8], 6)
	if err := object.AddSection(pdata); err != nil {
		t.Fatal(err)
	}
	textSymbol := object.GetSymbol(".text")
	for _, offset := range []uint32{0, 4} {
		pdata.Relocations = append(pdata.Relocations, &coff.Relocation{
			Section: pdata, VirtualAddress: offset, Symbol: textSymbol, SymbolName: textSymbol.Name, Type: coff.RelAMD64Addr32NB,
		})
	}

	result, _, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}})
	if err != nil {
		t.Fatal(err)
	}
	resultPdata := result.GetSection(".pdata")
	if got := binary.LittleEndian.Uint32(resultPdata.Data[4:8]); got != 2 {
		t.Fatalf("rebased runtime-function end = %d, want 2", got)
	}
	if len(resultPdata.Relocations) != 2 || resultPdata.Relocations[0].VirtualAddress != 0 || resultPdata.Relocations[1].VirtualAddress != 4 {
		t.Fatalf("pdata relocations = %#v", resultPdata.Relocations)
	}
	if got := binary.LittleEndian.Uint32(pdata.Data[4:8]); got != 6 {
		t.Fatalf("source pdata end changed to %d", got)
	}
}

func TestApplyExpandsFixedSizeInSamePass(t *testing.T) {
	replacement := []byte{0x90, 0xcc, 0x90, 0xcc, 0x90}
	object, text, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, replacement)
	result, report, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}})
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), replacement...), 0xc3)
	if !bytes.Equal(result.GetSection(".text").Data, want) || len(result.GetSection(".text").Relocations) != 0 {
		t.Fatalf("rewrite = %x with %d relocations, want %x with none", result.GetSection(".text").Data, len(result.GetSection(".text").Relocations), want)
	}
	if result.GetSymbol("__custom") != nil {
		t.Fatal("consumed unreferenced intrinsic symbol remains")
	}
	if len(report.Sites) != 1 || report.BytesDelta != 0 || report.Sites[0].OriginalLen != 5 || report.Sites[0].ResultLen != 5 {
		t.Fatalf("report = %#v", report)
	}
	if !bytes.Equal(text.Data, []byte{0xe8, 0, 0, 0, 0, 0xc3}) || len(text.Relocations) != 1 {
		t.Fatal("Apply mutated source while expanding a fixed-size intrinsic")
	}
}

func TestApplyArbitraryBytesDoNotForceSecondIntrinsicDecode(t *testing.T) {
	object, text, model := fixture(t, coff.MachineAMD64,
		[]byte{0xe8, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x0f})
	hashSymbol := &coff.Symbol{Name: "__ror13_Kernel32$Sleep", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(hashSymbol); err != nil {
		t.Fatal(err)
	}
	text.Relocations = append(text.Relocations, &coff.Relocation{
		Section: text, VirtualAddress: 6, Symbol: hashSymbol, SymbolName: hashSymbol.Name, Type: coff.RelAMD64Rel32,
	})
	hashExpansion, matched, resolveErr := model.ResolveIntrinsic(hooks.CallSite{
		HasRelocation: true, Symbol: hashSymbol.Name,
		Instruction: x86.Instruction{Bytes: []byte{0xe8, 0, 0, 0, 0}, Form: "CALL rel32"},
	})
	if resolveErr != nil || !matched {
		t.Fatalf("resolve hash = %#v, %v, %v", hashExpansion, matched, resolveErr)
	}
	result, report, err := Apply(context.Background(), object, model, Options{Disassembler: linearDecoder{}})
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x0f}, hashExpansion.Bytes...)
	want = append(want, 0xc3)
	if len(report.Sites) != 1 || !bytes.Equal(result.GetSection(".text").Data, want) || len(result.GetSection(".text").Relocations) != 0 {
		t.Fatalf("single-pass result/report = %x / %#v", result.GetSection(".text").Data, report)
	}
	// 0F B8... begins a different/truncated opcode stream. Upstream resolves
	// both sites before emitting it and does not run a second intrinsic decode.
	final, plan, err := hookencode.Apply(context.Background(), result, model)
	if err != nil {
		t.Fatalf("downstream fixed-size planner decoded resolved arbitrary bytes: %v", err)
	}
	if len(plan.Sites) != 0 || !bytes.Equal(final.GetSection(".text").Data, want) {
		t.Fatalf("downstream result/plan = %x / %#v", final.GetSection(".text").Data, plan)
	}
}

func TestApplyPreservesBuiltinPrecedence(t *testing.T) {
	object, _, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__ror13_Kernel32$Sleep", coff.RelAMD64Rel32, []byte{0x90})
	expansion, matched, resolveErr := model.ResolveIntrinsic(hooks.CallSite{
		HasRelocation: true, Symbol: "__ror13_Kernel32$Sleep",
		Instruction: x86.Instruction{Bytes: []byte{0xe8, 0, 0, 0, 0}, Form: "CALL rel32"},
	})
	if resolveErr != nil || !matched || expansion.Kind != hooks.ExpansionHashImmediate {
		t.Fatalf("built-in expansion = %#v, %v, %v", expansion, matched, resolveErr)
	}
	result, report, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}})
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), expansion.Bytes...), 0xc3)
	if len(report.Sites) != 0 || !bytes.Equal(result.GetSection(".text").Data, want) || len(result.GetSection(".text").Relocations) != 0 || result.GetSymbol("__ror13_Kernel32$Sleep") != nil {
		t.Fatalf("built-in precedence result: report=%#v text=%x relocs=%d symbol=%#v", report, result.GetSection(".text").Data, len(result.GetSection(".text").Relocations), result.GetSymbol("__ror13_Kernel32$Sleep"))
	}
}

func TestApplySkipsUserIntrinsicInGlobalDataGroup(t *testing.T) {
	object, text, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
	// Code.analyze's value-keyed label map lets the later alias win. Rebuilder
	// then treats this group as data and bypasses every AddInstruction pass.
	if err := object.AddSymbol(coff.NewDataSymbol(text, "blob", 0)); err != nil {
		t.Fatal(err)
	}
	result, report, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Sites) != 0 || !bytes.Equal(result.GetSection(".text").Data, text.Data) || len(result.GetSection(".text").Relocations) != 1 {
		t.Fatalf("data-group intrinsic was rewritten: report=%#v text=%x relocs=%d", report, result.GetSection(".text").Data, len(result.GetSection(".text").Relocations))
	}
	if result.GetSymbol("__custom") == nil {
		t.Fatal("still-referenced intrinsic symbol was removed")
	}
}

func TestApplyKeepsIntrinsicSymbolReferencedByDataGroup(t *testing.T) {
	object, text, model := fixture(t, coff.MachineAMD64,
		[]byte{0xe8, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
	if err := object.AddSymbol(coff.NewDataSymbol(text, "blob", 5)); err != nil {
		t.Fatal(err)
	}
	target := object.GetSymbol("__custom")
	text.Relocations = append(text.Relocations, &coff.Relocation{
		Section: text, VirtualAddress: 6, Symbol: target, SymbolName: target.Name, Type: coff.RelAMD64Rel32,
	})
	result, report, err := Apply(context.Background(), object, model, Options{Disassembler: linearDecoder{}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x90, 0xe8, 0, 0, 0, 0}; !bytes.Equal(result.GetSection(".text").Data, want) {
		t.Fatalf("output = %x, want %x", result.GetSection(".text").Data, want)
	}
	relocations := result.GetSection(".text").Relocations
	if len(report.Sites) != 1 || len(relocations) != 1 || relocations[0].VirtualAddress != 2 || result.GetSymbol("__custom") == nil {
		t.Fatalf("report/relocations/symbol = %#v / %#v / %#v", report, relocations, result.GetSymbol("__custom"))
	}
}

func TestApplyDecoderOwnership(t *testing.T) {
	newFixture := func(t *testing.T) (*coff.Object, *hooks.Model) {
		object, _, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
		return object, model
	}

	t.Run("caller owned", func(t *testing.T) {
		object, model := newFixture(t)
		var closes atomic.Int32
		decoder := linearDecoder{closeCalls: &closes}
		if _, _, err := Apply(context.Background(), object, model, Options{Disassembler: decoder}); err != nil {
			t.Fatal(err)
		}
		if got := closes.Load(); got != 0 {
			t.Fatalf("caller-owned decoder closed %d times", got)
		}
	})

	t.Run("factory owned", func(t *testing.T) {
		object, model := newFixture(t)
		var closes atomic.Int32
		factoryCalls := 0
		factory := func(_ context.Context, mode x86.Mode) (x86.Disassembler, error) {
			factoryCalls++
			if mode != x86.Mode64 {
				t.Fatalf("factory mode = %s, want x86-64", mode)
			}
			return linearDecoder{closeCalls: &closes}, nil
		}
		if _, _, err := Apply(context.Background(), object, model, Options{NewDisassembler: factory}); err != nil {
			t.Fatal(err)
		}
		if factoryCalls != 1 || closes.Load() != 1 {
			t.Fatalf("factory calls/closes = %d/%d, want 1/1", factoryCalls, closes.Load())
		}
	})

	t.Run("owned close error is transactional", func(t *testing.T) {
		object, model := newFixture(t)
		before := append([]byte(nil), object.GetSection(".text").Data...)
		var closes atomic.Int32
		closeFailure := errors.New("close failed")
		factory := func(context.Context, x86.Mode) (x86.Disassembler, error) {
			return linearDecoder{closeCalls: &closes, closeErr: closeFailure}, nil
		}
		result, _, err := Apply(context.Background(), object, model, Options{NewDisassembler: factory})
		if result != nil || !errors.Is(err, closeFailure) || closes.Load() != 1 {
			t.Fatalf("result/error/closes = %#v / %v / %d", result, err, closes.Load())
		}
		if !bytes.Equal(object.GetSection(".text").Data, before) || len(object.GetSection(".text").Relocations) != 1 {
			t.Fatal("decoder close failure mutated source")
		}
	})
}

func TestApplyRejectsAmbiguousCodeSymbolAndDuplicateRelocation(t *testing.T) {
	t.Run("ambiguous code symbol", func(t *testing.T) {
		object, text, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
		if err := object.AddSymbol(&coff.Symbol{Name: "candidate", Value: 1, Section: text, StorageClass: coff.SymbolClassStatic}); err != nil {
			t.Fatal(err)
		}
		before := append([]byte(nil), text.Data...)
		if result, _, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}}); result != nil || !errors.Is(err, ErrInvalidModel) {
			t.Fatalf("result/error = %#v / %v", result, err)
		}
		if !bytes.Equal(text.Data, before) || len(text.Relocations) != 1 {
			t.Fatal("ambiguous-symbol rejection mutated source")
		}
	})

	t.Run("multiple relocations in one instruction", func(t *testing.T) {
		object, text, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
		extra := &coff.Symbol{Name: "external", Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
		if err := object.AddSymbol(extra); err != nil {
			t.Fatal(err)
		}
		text.Relocations = append(text.Relocations, &coff.Relocation{
			Section: text, VirtualAddress: 2, Symbol: extra, SymbolName: extra.Name, Type: coff.RelAMD64Rel32,
		})
		before := append([]byte(nil), text.Data...)
		if result, _, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}}); result != nil || !errors.Is(err, ErrUnsupportedForm) {
			t.Fatalf("result/error = %#v / %v", result, err)
		}
		if !bytes.Equal(text.Data, before) || len(text.Relocations) != 2 {
			t.Fatal("duplicate-relocation rejection mutated source")
		}
	})

	t.Run("missing function boundary", func(t *testing.T) {
		object, text, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
		object.RemoveSymbols(map[string]struct{}{"go": {}})
		before := append([]byte(nil), text.Data...)
		if result, _, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}}); result != nil || !errors.Is(err, ErrInvalidModel) || !errors.Is(err, ised.ErrInvalidObject) {
			t.Fatalf("result/error = %#v / %v", result, err)
		}
		if !bytes.Equal(text.Data, before) || len(text.Relocations) != 1 {
			t.Fatal("missing-boundary rejection mutated source")
		}
	})
}

func TestApplyRelocationSymbolIdentity(t *testing.T) {
	t.Run("pointer-only name", func(t *testing.T) {
		object, text, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
		text.Relocations[0].SymbolName = ""
		result, report, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}})
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Sites) != 1 || !bytes.Equal(result.GetSection(".text").Data, []byte{0x90, 0xc3}) {
			t.Fatalf("result/report = %x / %#v", result.GetSection(".text").Data, report)
		}
	})

	t.Run("mismatched name and pointer", func(t *testing.T) {
		object, text, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
		text.Relocations[0].SymbolName = "__different"
		before := append([]byte(nil), text.Data...)
		if result, _, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}}); result != nil || !errors.Is(err, ErrInvalidModel) {
			t.Fatalf("result/error = %#v / %v", result, err)
		}
		if !bytes.Equal(text.Data, before) || len(text.Relocations) != 1 {
			t.Fatal("identity rejection mutated source")
		}
	})
}

func TestApplyRejectsMalformedSiteTransactionally(t *testing.T) {
	object, text, model := fixture(t, coff.MachineAMD64, []byte{0xff, 0xd0, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
	before := append([]byte(nil), text.Data...)
	_, _, err := Apply(context.Background(), object, model, Options{})
	if !errors.Is(err, ErrUnsupportedForm) {
		t.Fatalf("error = %v, want ErrUnsupportedForm", err)
	}
	if !bytes.Equal(text.Data, before) || len(text.Relocations) != 1 {
		t.Fatal("failed Apply mutated source")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Apply(cancelled, object, model, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if _, _, err := Apply(nil, object, model, Options{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, _, err := Apply(context.Background(), object, model, Options{
		Disassembler: fixedCallDecoder{},
		NewDisassembler: func(context.Context, x86.Mode) (x86.Disassembler, error) {
			return fixedCallDecoder{}, nil
		},
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mutually exclusive decoder options error = %v", err)
	}
}

func TestApplyConcurrentDeterminism(t *testing.T) {
	object, _, model := fixture(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, "__custom", coff.RelAMD64Rel32, []byte{0x90})
	const workers = 4
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, report, err := Apply(context.Background(), object, model, Options{Disassembler: fixedCallDecoder{}})
			if err != nil {
				errorsChannel <- err
				return
			}
			if !bytes.Equal(result.GetSection(".text").Data, []byte{0x90, 0xc3}) || len(report.Sites) != 1 {
				errorsChannel <- errors.New("nondeterministic intrinsic result")
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}

func fixture(t *testing.T, machine coff.Machine, code []byte, intrinsic string, relocationType uint16, replacement []byte) (*coff.Object, *coff.Section, *hooks.Model) {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", code)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(coff.NewFunctionSymbol(text, entryName(machine), 0)); err != nil {
		t.Fatal(err)
	}
	target := &coff.Symbol{Name: intrinsic, Type: coff.SymbolTypeFunction, StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(target); err != nil {
		t.Fatal(err)
	}
	text.Relocations = []*coff.Relocation{{
		Section: text, VirtualAddress: 1, SymbolName: target.Name, Symbol: target, Type: relocationType,
	}}
	model, err := hooks.New(object)
	if err != nil {
		t.Fatal(err)
	}
	model = addUserIntrinsic(t, model, object, intrinsic, replacement)
	return object, text, model
}

func addUserIntrinsic(t testing.TB, model *hooks.Model, object *coff.Object, intrinsic string, replacement []byte) *hooks.Model {
	t.Helper()
	directive, err := hooks.Parse("intrinsic", []string{intrinsic, "$CODE"})
	if err != nil {
		t.Fatal(err)
	}
	model, err = model.ApplyResolved(context.Background(), object, directive, replacement)
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func entryName(machine coff.Machine) string {
	if machine == coff.MachineI386 {
		return "_go"
	}
	return "go"
}
