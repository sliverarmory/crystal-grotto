// SPDX-License-Identifier: GPL-3.0-only

package btf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestGoFirstAndDiscoRebaseSymbolsAndRelocations(t *testing.T) {
	t.Parallel()
	object := testObject(t)
	// Zeroes make the Fisher-Yates choices deterministic: each iteration swaps
	// with the first eligible chunk.
	random := bytes.NewReader(make([]byte, 32))
	report, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", GoFirst: true, Disco: true, PreserveFirst: true, Random: random})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"go", "helper", "table", "unused"}; !reflect.DeepEqual(report.FinalOrder, want) {
		t.Fatalf("final order = %#v, want %#v", report.FinalOrder, want)
	}
	if got, want := object.GetSection(".text").Data, []byte{0x30, 0, 0, 0, 0, 0x31, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x40, 0x41, 0x10, 0x11}; !bytes.Equal(got, want) {
		t.Fatalf("text = %x, want %x", got, want)
	}
	if got := object.GetSymbol("go").Value; got != 0 {
		t.Fatalf("go value = %d", got)
	}
	if got := object.GetSymbol("helper").Value; got != 6 {
		t.Fatalf("helper value = %d", got)
	}
	if got := object.GetSection(".text").Relocations[0].VirtualAddress; got != 1 {
		t.Fatalf("go relocation = %d", got)
	}
}

func TestOptimizeKeepsReachableFunctionsAndData(t *testing.T) {
	t.Parallel()
	object := testObject(t)
	report, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", Optimize: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"unused"}; !reflect.DeepEqual(report.Removed, want) {
		t.Fatalf("removed = %#v, want %#v", report.Removed, want)
	}
	if object.GetSymbol("unused") != nil {
		t.Fatal("unused symbol remains")
	}
	if got, want := object.GetSection(".text").Data, []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x30, 0, 0, 0, 0, 0x31, 0x40, 0x41}; !bytes.Equal(got, want) {
		t.Fatalf("text = %x, want %x", got, want)
	}
	if got := object.GetSymbol("go").Value; got != 6 {
		t.Fatalf("go value = %d, want 6", got)
	}
}

func TestOptimizeRequiresRoot(t *testing.T) {
	t.Parallel()
	object := testObject(t)
	if _, err := ApplyOrderPasses(object, OrderOptions{Entry: "missing", Optimize: true}); err == nil {
		t.Fatal("ApplyOrderPasses succeeded")
	}
}

func TestOptimizeFollowsRelocationFreeDirectControlFlowAndRepairsDisplacement(t *testing.T) {
	for _, machine := range []coff.Machine{coff.MachineI386, coff.MachineAMD64} {
		machine := machine
		for _, opcode := range []byte{0xe8, 0xe9} {
			opcode := opcode
			t.Run(machine.String()+"/"+map[byte]string{0xe8: "call", 0xe9: "jmp"}[opcode], func(t *testing.T) {
				entry := "go"
				mode := x86.Mode64
				if machine == coff.MachineI386 {
					entry, mode = "_go", x86.Mode32
				}
				decoder, err := x86.NewCapstone(context.Background(), mode)
				if err != nil {
					t.Fatal(err)
				}
				defer decoder.Close(context.Background())

				// entry -> helper crosses dead. Once dead is removed the rel32
				// displacement must shrink from 7 to 1. There is deliberately no
				// COFF relocation: linker.Merge has already consumed it.
				object := orderObject(t, machine,
					[]byte{opcode, 7, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3, 0xb8, 42, 0, 0, 0, 0xc3},
					coff.NewFunctionSymbol(nil, entry, 0),
					coff.NewFunctionSymbol(nil, "dead", 6),
					coff.NewFunctionSymbol(nil, "helper", 12),
				)
				report, err := ApplyOrderPasses(object, OrderOptions{Entry: entry, Optimize: true, Disassembler: decoder})
				if err != nil {
					t.Fatal(err)
				}
				if want := []string{"dead"}; !reflect.DeepEqual(report.Removed, want) {
					t.Fatalf("removed = %#v, want %#v", report.Removed, want)
				}
				text := object.GetSection(".text")
				if got := int32(binary.LittleEndian.Uint32(text.Data[1:5])); got != 1 {
					t.Fatalf("repaired displacement = %d, want 1; text=%x", got, text.Data)
				}
				if helper := object.GetSymbol("helper"); helper == nil || helper.Value != 6 {
					t.Fatalf("helper = %#v, want offset 6", helper)
				}
			})
		}
	}
}

func TestGoFirstRepairsRelocationFreeCall(t *testing.T) {
	object := orderObject(t, coff.MachineAMD64,
		[]byte{0xc3, 0xe8, 0xfa, 0xff, 0xff, 0xff, 0xc3},
		coff.NewFunctionSymbol(nil, "helper", 0),
		coff.NewFunctionSymbol(nil, "go", 1),
	)
	if _, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", GoFirst: true}); err != nil {
		t.Fatal(err)
	}
	text := object.GetSection(".text")
	if got := int32(binary.LittleEndian.Uint32(text.Data[1:5])); got != 1 {
		t.Fatalf("repaired displacement = %d, want 1; text=%x", got, text.Data)
	}
	if got := object.GetSymbol("go").Value; got != 0 {
		t.Fatalf("go offset = %d, want 0", got)
	}
}

func TestGoFirstThenOptimizeFollowsRelocatedCallAfterChunkReorder(t *testing.T) {
	object := orderObject(t, coff.MachineAMD64,
		[]byte{0xc3, 0xe8, 0, 0, 0, 0, 0xc3, 0xc3},
		coff.NewFunctionSymbol(nil, "helper", 0),
		coff.NewFunctionSymbol(nil, "go", 1),
		coff.NewFunctionSymbol(nil, "dead", 7),
	)
	text := object.GetSection(".text")
	text.Relocations = []*coff.Relocation{{
		Section: text, VirtualAddress: 2, SymbolName: "helper",
		Symbol: object.GetSymbol("helper"), Type: coff.RelAMD64Rel32,
	}}
	report, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", GoFirst: true, Optimize: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"dead"}; !reflect.DeepEqual(report.Removed, want) {
		t.Fatalf("removed = %#v, want %#v", report.Removed, want)
	}
	if helper := object.GetSymbol("helper"); helper == nil || helper.Value != 6 {
		t.Fatalf("helper = %#v, want offset 6", helper)
	}
	if got := text.Relocations[0].VirtualAddress; got != 1 {
		t.Fatalf("relocation offset = %d, want 1", got)
	}
}

func TestDiscoRepairsRelocationFreeCall(t *testing.T) {
	object := orderObject(t, coff.MachineAMD64,
		[]byte{0xe8, 2, 0, 0, 0, 0xc3, 0xc3, 0xc3},
		coff.NewFunctionSymbol(nil, "go", 0),
		coff.NewFunctionSymbol(nil, "dead", 6),
		coff.NewFunctionSymbol(nil, "helper", 7),
	)
	if _, err := ApplyOrderPasses(object, OrderOptions{
		Entry: "go", Disco: true, PreserveFirst: true, Random: bytes.NewReader(make([]byte, 8)),
	}); err != nil {
		t.Fatal(err)
	}
	text := object.GetSection(".text")
	if got := int32(binary.LittleEndian.Uint32(text.Data[1:5])); got != 1 {
		t.Fatalf("repaired displacement = %d, want 1; text=%x", got, text.Data)
	}
	if got := object.GetSymbol("helper").Value; got != 6 {
		t.Fatalf("helper offset = %d, want 6", got)
	}
}

func TestOptimizeFollowsAndRepairsRIPRelativeReference(t *testing.T) {
	object := orderObject(t, coff.MachineAMD64,
		[]byte{0x48, 0x8d, 0x05, 2, 0, 0, 0, 0xc3, 0xc3, 0xc3},
		coff.NewFunctionSymbol(nil, "go", 0),
		coff.NewFunctionSymbol(nil, "dead", 8),
		coff.NewFunctionSymbol(nil, "helper", 9),
	)
	report, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", Optimize: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"dead"}; !reflect.DeepEqual(report.Removed, want) {
		t.Fatalf("removed = %#v, want %#v", report.Removed, want)
	}
	text := object.GetSection(".text")
	if got := int32(binary.LittleEndian.Uint32(text.Data[3:7])); got != 1 {
		t.Fatalf("repaired RIP displacement = %d, want 1; text=%x", got, text.Data)
	}
	if helper := object.GetSymbol("helper"); helper == nil || helper.Value != 8 {
		t.Fatalf("helper = %#v, want offset 8", helper)
	}
}

func TestOptimizeCatchHandlerIsARoot(t *testing.T) {
	object := orderObject(t, coff.MachineAMD64, []byte{0xc3, 0xc3, 0xc3},
		coff.NewFunctionSymbol(nil, "go", 0),
		coff.NewFunctionSymbol(nil, "handler", 1),
		coff.NewFunctionSymbol(nil, "dead", 2),
	)
	report, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", Optimize: true, CatchHandlers: []string{"handler"}})
	if err != nil {
		t.Fatal(err)
	}
	if object.GetSymbol("handler") == nil {
		t.Fatal("catch handler was optimized away")
	}
	if want := []string{"dead"}; !reflect.DeepEqual(report.Removed, want) {
		t.Fatalf("removed = %#v, want %#v", report.Removed, want)
	}
}

func TestOptimizeTrimsTrailingNOPAndINT3PaddingLikeUpstream(t *testing.T) {
	for _, machine := range []coff.Machine{coff.MachineI386, coff.MachineAMD64} {
		machine := machine
		t.Run(machine.String(), func(t *testing.T) {
			entry := "go"
			if machine == coff.MachineI386 {
				entry = "_go"
			}
			// This mirrors LinkTimeOptimizer.java: a retained function loses
			// its entire terminal instruction run when every instruction in the
			// run has Iced's exact zero-operand NOP or INT3 opcode form.
			object := orderObject(t, machine, []byte{
				0xe8, 7, 0, 0, 0, 0xc3, 0x90, 0x90, 0xcc,
				0xc3, 0x90, 0xcc,
				0xb8, 42, 0, 0, 0, 0xc3, 0x90, 0x90, 0xcc,
			},
				coff.NewFunctionSymbol(nil, entry, 0),
				coff.NewFunctionSymbol(nil, "dead", 9),
				coff.NewFunctionSymbol(nil, "helper", 12),
			)
			text := object.GetSection(".text")
			for _, name := range []string{entry, "helper"} {
				symbol := object.GetSymbol(name)
				symbol.AuxiliaryRecords = [][]byte{make([]byte, 18)}
				binary.LittleEndian.PutUint32(symbol.AuxiliaryRecords[0][4:8], symbol.EstimateSize())
			}
			external := &coff.Symbol{Name: "external", StorageClass: coff.SymbolClassExternal}
			if err := object.AddSymbol(external); err != nil {
				t.Fatal(err)
			}
			relocationType := coff.RelAMD64Addr32NB
			if machine == coff.MachineI386 {
				relocationType = coff.RelI386Dir32
			}
			text.Relocations = []*coff.Relocation{{
				Section: text, VirtualAddress: 13, SymbolName: external.Name,
				Symbol: external, Type: relocationType,
			}}
			text.VirtualSize = uint32(len(text.Data))
			report, err := ApplyOrderPasses(object, OrderOptions{Entry: entry, Optimize: true})
			if err != nil {
				t.Fatal(err)
			}
			if want := []string{"dead"}; !reflect.DeepEqual(report.Removed, want) {
				t.Fatalf("removed = %#v, want %#v", report.Removed, want)
			}
			want := []byte{0xe8, 1, 0, 0, 0, 0xc3, 0xb8, 42, 0, 0, 0, 0xc3}
			if !bytes.Equal(text.Data, want) {
				t.Fatalf("optimized text = %x, want %x", text.Data, want)
			}
			if text.SizeOfRawData != uint32(len(want)) || text.VirtualSize != uint32(len(want)) {
				t.Fatalf("optimized sizes = raw:%d virtual:%d, want %d", text.SizeOfRawData, text.VirtualSize, len(want))
			}
			if helper := object.GetSymbol("helper"); helper == nil || helper.Value != 6 {
				t.Fatalf("helper = %#v, want offset 6", helper)
			}
			for _, name := range []string{entry, "helper"} {
				if got := binary.LittleEndian.Uint32(object.GetSymbol(name).AuxiliaryRecords[0][4:8]); got != 6 {
					t.Fatalf("%s auxiliary size = %d, want 6", name, got)
				}
			}
			if len(text.Relocations) != 1 || text.Relocations[0].VirtualAddress != 7 {
				t.Fatalf("rebased relocations = %#v, want one at offset 7", text.Relocations)
			}
		})
	}
}

func TestOptimizeDoesNotTrimOperandBearingNOP(t *testing.T) {
	for _, machine := range []coff.Machine{coff.MachineI386, coff.MachineAMD64} {
		entry := "go"
		if machine == coff.MachineI386 {
			entry = "_go"
		}
		object := orderObject(t, machine, []byte{0xc3, 0x0f, 0x1f, 0x00},
			coff.NewFunctionSymbol(nil, entry, 0))
		if _, err := ApplyOrderPasses(object, OrderOptions{Entry: entry, Optimize: true}); err != nil {
			t.Fatal(err)
		}
		if got, want := object.GetSection(".text").Data, []byte{0xc3, 0x0f, 0x1f, 0x00}; !bytes.Equal(got, want) {
			t.Fatalf("%s operand-bearing NOP was trimmed: got %x", machine, got)
		}
	}
}

func TestOptimizeFailsTransactionallyWhenBranchTargetsTrimmedPadding(t *testing.T) {
	object := orderObject(t, coff.MachineAMD64, []byte{0xeb, 1, 0xc3, 0x90},
		coff.NewFunctionSymbol(nil, "go", 0))
	text := object.GetSection(".text")
	before := append([]byte(nil), text.Data...)
	_, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", Optimize: true})
	if !errors.Is(err, ErrReferencedOptimizedPadding) {
		t.Fatalf("error = %v, want ErrReferencedOptimizedPadding", err)
	}
	var reference *ReferencedOptimizedPaddingError
	if !errors.As(err, &reference) || reference.Target != 3 || reference.Function != "go" {
		t.Fatalf("typed error = %#v", reference)
	}
	if !bytes.Equal(text.Data, before) || object.GetSymbol("go").Value != 0 {
		t.Fatal("failed padding trim mutated the object")
	}
}

func TestOptimizeFailsWhenRelocationTargetsTrimmedPadding(t *testing.T) {
	object := orderObject(t, coff.MachineAMD64, []byte{0xc3, 0x90},
		coff.NewFunctionSymbol(nil, "go", 0))
	rdata := coff.NewSection(".rdata", []byte{1, 0, 0, 0})
	if err := object.AddSection(rdata); err != nil {
		t.Fatal(err)
	}
	rdata.Relocations = []*coff.Relocation{{
		Section: rdata, VirtualAddress: 0, SymbolName: ".text",
		Symbol: object.GetSymbol(".text"), Type: coff.RelAMD64Addr32NB,
	}}
	_, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", Optimize: true})
	if !errors.Is(err, ErrReferencedOptimizedPadding) {
		t.Fatalf("error = %v, want ErrReferencedOptimizedPadding", err)
	}
	if got := object.GetSection(".text").Data; !bytes.Equal(got, []byte{0xc3, 0x90}) {
		t.Fatalf("failed trim changed text to %x", got)
	}
}

func TestOrderingFailsClosedAndDoesNotMutateUnprovenRIPReference(t *testing.T) {
	object := orderObject(t, coff.MachineAMD64,
		[]byte{0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3},
		coff.NewFunctionSymbol(nil, "go", 0),
	)
	before := append([]byte(nil), object.GetSection(".text").Data...)
	_, err := ApplyOrderPasses(object, OrderOptions{Entry: "go", Disco: true})
	if !errors.Is(err, ErrUnprovenOrderReference) {
		t.Fatalf("error = %v, want ErrUnprovenOrderReference", err)
	}
	if !bytes.Equal(object.GetSection(".text").Data, before) || object.GetSymbol("go").Value != 0 {
		t.Fatal("failed ordering mutated the object")
	}
}

func testObject(t *testing.T) *coff.Object {
	t.Helper()
	object, err := coff.NewObject(coff.MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", []byte{0x10, 0x11, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x30, 0, 0, 0, 0, 0x31, 0x40, 0x41})
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	for _, symbol := range []*coff.Symbol{
		coff.NewFunctionSymbol(text, "unused", 0),
		coff.NewFunctionSymbol(text, "helper", 2),
		coff.NewFunctionSymbol(text, "go", 8),
		coff.NewDataSymbol(text, "table", 14),
	} {
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
	}
	// go calls helper. The stored addend is irrelevant to reachability but
	// represents an ordinary REL32 patch site.
	binary.LittleEndian.PutUint32(text.Data[9:13], 0)
	text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 9, SymbolName: "helper", Symbol: object.GetSymbol("helper"), Type: coff.RelAMD64Rel32}}
	return object
}

func orderObject(t *testing.T, machine coff.Machine, data []byte, symbols ...*coff.Symbol) *coff.Object {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", data)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	for _, symbol := range symbols {
		symbol.Section = text
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
	}
	return object
}
