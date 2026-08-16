// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package safety

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

var (
	sharedX86     *x86.Capstone
	sharedX64     *x86.Capstone
	sharedX86Err  error
	sharedX64Err  error
	sharedX86Once sync.Once
	sharedX64Once sync.Once
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	status := m.Run()
	if sharedX64 != nil {
		if err := sharedX64.Close(ctx); err != nil && status == 0 {
			fmt.Fprintln(os.Stderr, err)
			status = 1
		}
	}
	if sharedX86 != nil {
		if err := sharedX86.Close(ctx); err != nil && status == 0 {
			fmt.Fprintln(os.Stderr, err)
			status = 1
		}
	}
	os.Exit(status)
}

func decoderOptions(machine coff.Machine) Options {
	if machine == coff.MachineI386 {
		sharedX86Once.Do(func() {
			sharedX86, sharedX86Err = x86.NewCapstone(context.Background(), x86.Mode32)
		})
		if sharedX86Err != nil {
			panic(sharedX86Err)
		}
		return Options{Disassembler: sharedX86}
	}
	sharedX64Once.Do(func() {
		sharedX64, sharedX64Err = x86.NewCapstone(context.Background(), x86.Mode64)
	})
	if sharedX64Err != nil {
		panic(sharedX64Err)
	}
	return Options{Disassembler: sharedX64}
}

func TestDangerWalkTransitiveExactAdvice(t *testing.T) {
	tests := []struct {
		name      string
		machine   coff.Machine
		root      string
		find      string
		leaf      string
		dprintf   string
		wantError string
	}{
		{
			name:    "x64",
			machine: coff.MachineAMD64,
			root:    "resolve",
			find:    "findFunctionByHash",
			leaf:    "debug",
			dprintf: "dprintf",
			wantError: "Don't call dprintf from dfr/fixptrs/fixbss. OutputDebugStringA's message propagation (SEHs) can corrupt from these contexts. " +
				"(resolve -> findFunctionByHash -> debug) [Use protect \"findFunctionByHash\" to opt this function out of attach hooks.]",
		},
		{
			name:    "x86",
			machine: coff.MachineI386,
			root:    "_resolve",
			find:    "_findFunctionByHash",
			leaf:    "_debug",
			dprintf: "_dprintf",
			wantError: "Don't call dprintf from dfr/fixptrs/fixbss. OutputDebugStringA's message propagation (SEHs) can corrupt from these contexts. " +
				"(_resolve -> _findFunctionByHash -> _debug) [Use protect \"_findFunctionByHash\" to opt this function out of attach hooks.]",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code := slotCode(4)
			putCall(code, 0, 8)
			putCall(code, 8, 16)
			putCall(code, 16, 24)
			object, _ := objectWithFunctions(t, test.machine, code, map[string]uint32{
				test.root: 0, test.find: 8, test.leaf: 16, test.dprintf: 24,
			})

			_, err := CheckRoot(context.Background(), object, test.root, decoderOptions(test.machine))
			if err == nil {
				t.Fatal("CheckRoot succeeded, want danger error")
			}
			if !errors.Is(err, ErrDangerousDprintf) || errors.Is(err, ErrUnproven) {
				t.Fatalf("error classification = %v", err)
			}
			var danger *DangerError
			if !errors.As(err, &danger) {
				t.Fatalf("error type = %T, want *DangerError", err)
			}
			if danger.Root != test.root || danger.Parent != test.leaf || danger.Symbol != test.dprintf {
				t.Fatalf("danger = %#v", danger)
			}
			if got := err.Error(); got != test.wantError {
				t.Fatalf("error = %q\nwant  = %q", got, test.wantError)
			}
		})
	}
}

func TestDangerWalkWithoutFindFunctionAdvice(t *testing.T) {
	code := slotCode(3)
	putCall(code, 0, 8)
	putCall(code, 8, 16)
	object, _ := objectWithFunctions(t, coff.MachineAMD64, code, map[string]uint32{
		"resolve": 0, "debug": 8, "dprintf": 16,
	})
	_, err := CheckRoot(context.Background(), object, "resolve", decoderOptions(coff.MachineAMD64))
	want := "Don't call dprintf from dfr/fixptrs/fixbss. OutputDebugStringA's message propagation (SEHs) can corrupt from these contexts. (resolve -> debug)"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestGraphMultipleRootsCycleAndDefensiveResults(t *testing.T) {
	code := slotCode(3)
	putCall(code, 0, 8)
	putCall(code, 8, 0)
	object, _ := objectWithFunctions(t, coff.MachineAMD64, code, map[string]uint32{
		"root": 0, "cycle": 8, "other": 16,
	})
	graph, err := BuildGraph(context.Background(), object, decoderOptions(coff.MachineAMD64))
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}
	if graph.Machine() != coff.MachineAMD64 {
		t.Fatalf("Machine = %v", graph.Machine())
	}
	wantFunctions := []string{"root", "cycle", "other"}
	if got := graph.Functions(); fmt.Sprint(got) != fmt.Sprint(wantFunctions) {
		t.Fatalf("Functions = %v, want %v", got, wantFunctions)
	}
	edges := graph.Edges()
	if len(edges) != 2 || edges[0].Kind != EdgeDirectCall || edges[1].Kind != EdgeDirectCall {
		t.Fatalf("Edges = %#v", edges)
	}
	report, err := graph.Check(context.Background(), "other", "root", "root")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got, want := fmt.Sprint(report.Roots), "[other root]"; got != want {
		t.Fatalf("Roots = %s, want %s", got, want)
	}
	if got, want := fmt.Sprint(report.Visited), "[other root cycle]"; got != want {
		t.Fatalf("Visited = %s, want %s", got, want)
	}

	functions := graph.Functions()
	functions[0] = "corrupt"
	edges[0].To = "corrupt"
	report.Roots[0] = "corrupt"
	if graph.Functions()[0] != "root" || graph.Edges()[0].To != "cycle" {
		t.Fatal("graph getters exposed internal slices")
	}
	report2, err := graph.Check(context.Background(), "other")
	if err != nil || report2.Roots[0] != "other" {
		t.Fatalf("second Check = %#v, %v", report2, err)
	}
}

func TestX64RIPRelativeCallWalkForms(t *testing.T) {
	tests := []struct {
		name string
		root []byte
		kind EdgeKind
	}{
		{name: "lea", root: []byte{0x48, 0x8d, 0x05, 0x01, 0x00, 0x00, 0x00, 0xc3}, kind: EdgeRIPReference},
		{name: "mov", root: []byte{0x48, 0x8b, 0x05, 0x01, 0x00, 0x00, 0x00, 0xc3}, kind: EdgeRIPReference},
		{name: "call", root: []byte{0xff, 0x15, 0x02, 0x00, 0x00, 0x00, 0xc3, 0x90}, kind: EdgeDirectCall},
		{name: "jmp", root: []byte{0xff, 0x25, 0x02, 0x00, 0x00, 0x00, 0xc3, 0x90}, kind: EdgeDirectJump},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code := slotCode(3)
			copy(code, test.root)
			putCall(code, 8, 16)
			object, _ := objectWithFunctions(t, coff.MachineAMD64, code, map[string]uint32{
				"root": 0, "leaf": 8, "dprintf": 16,
			})
			graph, err := BuildGraph(context.Background(), object, decoderOptions(coff.MachineAMD64))
			if err != nil {
				t.Fatalf("BuildGraph: %v", err)
			}
			if edges := graph.Edges(); len(edges) < 2 || edges[0] != (Edge{From: "root", To: "leaf", Offset: 0, Kind: test.kind}) {
				t.Fatalf("Edges = %#v", edges)
			}
			if _, err := graph.Check(context.Background(), "root"); !errors.Is(err, ErrDangerousDprintf) {
				t.Fatalf("Check error = %v", err)
			}
		})
	}
}

func TestReferencePointerTargetsX86AndX64(t *testing.T) {
	tests := []struct {
		name      string
		machine   coff.Machine
		code      []byte
		root      string
		dprintf   string
		relocAt   uint32
		relocType uint16
	}{
		{
			name: "x64", machine: coff.MachineAMD64,
			code: []byte{0x48, 0x8b, 0x05, 0x01, 0, 0, 0, 0xc3, 0xc3},
			root: "root", dprintf: "dprintf", relocAt: 3, relocType: coff.RelAMD64Rel32,
		},
		{
			name: "x86", machine: coff.MachineI386,
			code: []byte{0xa1, 0, 0, 0, 0, 0xc3, 0x90, 0x90, 0xc3},
			root: "_root", dprintf: "_dprintf", relocAt: 1, relocType: coff.RelI386Dir32,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object, text := objectWithFunctions(t, test.machine, test.code, map[string]uint32{
				test.root: 0, test.dprintf: 8,
			})
			rdata := coff.NewSection(".rdata", make([]byte, 8))
			if err := object.AddSection(rdata); err != nil {
				t.Fatal(err)
			}
			refptr := coff.NewDataSymbol(rdata, ".refptr."+test.dprintf, 0)
			if err := object.AddSymbol(refptr); err != nil {
				t.Fatal(err)
			}
			text.Relocations = append(text.Relocations, &coff.Relocation{
				Section: text, VirtualAddress: test.relocAt, SymbolName: refptr.Name, Symbol: refptr, Type: test.relocType,
			})
			graph, err := BuildGraph(context.Background(), object, decoderOptions(test.machine))
			if err != nil {
				t.Fatalf("BuildGraph: %v", err)
			}
			if got := graph.Edges(); len(got) != 1 || got[0].Kind != EdgeReferencePointer || got[0].To != test.dprintf {
				t.Fatalf("Edges = %#v", got)
			}
			if _, err := graph.Check(context.Background(), test.root); !errors.Is(err, ErrDangerousDprintf) {
				t.Fatalf("Check error = %v", err)
			}
		})
	}
}

func TestLocalRelocationTargets(t *testing.T) {
	t.Run("x86 section symbol addend", func(t *testing.T) {
		code := slotCode(3)
		putCall(code, 0, 8)
		putCall(code, 8, 16)
		object, text := objectWithFunctions(t, coff.MachineI386, code, map[string]uint32{
			"_root": 0, "_leaf": 8, "_dprintf": 16,
		})
		text.Data[1], text.Data[2], text.Data[3], text.Data[4] = 8, 0, 0, 0
		sectionSymbol := findSymbol(t, object, ".text")
		text.Relocations = append(text.Relocations, &coff.Relocation{
			Section: text, VirtualAddress: 1, SymbolName: ".text", Symbol: sectionSymbol, Type: coff.RelI386Rel32,
		})
		graph, err := BuildGraph(context.Background(), object, decoderOptions(coff.MachineI386))
		if err != nil {
			t.Fatalf("BuildGraph: %v", err)
		}
		if edge := graph.Edges()[0]; edge.From != "_root" || edge.To != "_leaf" || edge.Kind != EdgeRelocation {
			t.Fatalf("first edge = %#v", edge)
		}
		if _, err := graph.Check(context.Background(), "_root"); !errors.Is(err, ErrDangerousDprintf) {
			t.Fatalf("Check error = %v", err)
		}
	})

	t.Run("x64 named local", func(t *testing.T) {
		code := slotCode(3)
		putCall(code, 0, 8)
		putCall(code, 8, 16)
		object, text := objectWithFunctions(t, coff.MachineAMD64, code, map[string]uint32{
			"root": 0, "leaf": 8, "dprintf": 16,
		})
		leaf := findSymbol(t, object, "leaf")
		for index := 1; index < 5; index++ {
			code[index] = 0
			text.Data[index] = 0
		}
		text.Relocations = append(text.Relocations, &coff.Relocation{
			Section: text, VirtualAddress: 1, SymbolName: "leaf", Symbol: leaf, Type: coff.RelAMD64Rel32,
		})
		graph, err := BuildGraph(context.Background(), object, decoderOptions(coff.MachineAMD64))
		if err != nil {
			t.Fatalf("BuildGraph: %v", err)
		}
		if edge := graph.Edges()[0]; edge.From != "root" || edge.To != "leaf" || edge.Kind != EdgeRelocation {
			t.Fatalf("first edge = %#v", edge)
		}
		if _, err := graph.Check(context.Background(), "root"); !errors.Is(err, ErrDangerousDprintf) {
			t.Fatalf("Check error = %v", err)
		}
	})
}

func TestMalformedAndUnprovenInputs(t *testing.T) {
	tests := []struct {
		name     string
		make     func(*testing.T) (*coff.Object, Options)
		contains string
	}{
		{
			name: "truncated instruction",
			make: func(t *testing.T) (*coff.Object, Options) {
				object, _ := objectWithFunctions(t, coff.MachineAMD64, []byte{0xe8, 0, 0}, map[string]uint32{"root": 0})
				return object, decoderOptions(coff.MachineAMD64)
			},
			contains: "disassembly",
		},
		{
			name: "indirect register call",
			make: func(t *testing.T) (*coff.Object, Options) {
				object, _ := objectWithFunctions(t, coff.MachineAMD64, []byte{0xff, 0xd0, 0xc3}, map[string]uint32{"root": 0})
				return object, decoderOptions(coff.MachineAMD64)
			},
			contains: "indirect control-flow",
		},
		{
			name: "relocation outside instruction",
			make: func(t *testing.T) (*coff.Object, Options) {
				object, text := objectWithFunctions(t, coff.MachineI386, []byte{0x90, 0xc3}, map[string]uint32{"_root": 0})
				text.Relocations = append(text.Relocations, &coff.Relocation{Section: text, VirtualAddress: 1, SymbolName: "external", Type: coff.RelI386Dir32})
				return object, decoderOptions(coff.MachineI386)
			},
			contains: "relocation",
		},
		{
			name: "unsupported relocation",
			make: func(t *testing.T) (*coff.Object, Options) {
				object, text := objectWithFunctions(t, coff.MachineAMD64, []byte{0x90, 0x90, 0x90, 0x90, 0xc3}, map[string]uint32{"root": 0})
				text.Relocations = append(text.Relocations, &coff.Relocation{Section: text, VirtualAddress: 0, SymbolName: "external", Type: 0xffff})
				return object, decoderOptions(coff.MachineAMD64)
			},
			contains: "unsupported x64 relocation",
		},
		{
			name: "function inside instruction",
			make: func(t *testing.T) (*coff.Object, Options) {
				object, _ := objectWithFunctions(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, map[string]uint32{"root": 0, "inside": 1})
				return object, decoderOptions(coff.MachineAMD64)
			},
			contains: "instruction boundary",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object, options := test.make(t)
			_, err := CheckRoot(context.Background(), object, rootFor(object.Machine), options)
			if err == nil || !errors.Is(err, ErrUnproven) {
				t.Fatalf("error = %v, want ErrUnproven", err)
			}
			var analysis *AnalysisError
			if !errors.As(err, &analysis) {
				t.Fatalf("error type = %T, want *AnalysisError", err)
			}
			if !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %q, want substring %q", err, test.contains)
			}
		})
	}

	if _, err := BuildGraph(nil, nil, Options{}); !errors.Is(err, x86.ErrNilContext) || !errors.Is(err, ErrUnproven) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := BuildGraph(context.Background(), nil, Options{}); !errors.Is(err, ErrUnproven) {
		t.Fatalf("nil object error = %v", err)
	}
	arm, err := coff.NewObject(coff.MachineARM64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildGraph(context.Background(), arm, Options{}); !errors.Is(err, ErrUnproven) {
		t.Fatalf("ARM64 error = %v", err)
	}
}

func TestCancellationDecoderOwnershipAndWalkValidation(t *testing.T) {
	t.Run("default decoder", func(t *testing.T) {
		object, _ := objectWithFunctions(t, coff.MachineAMD64, []byte{0xc3}, map[string]uint32{"root": 0})
		graph, err := BuildGraph(context.Background(), object, Options{})
		if err != nil {
			t.Fatalf("BuildGraph: %v", err)
		}
		if _, err := graph.Check(context.Background(), "root"); err != nil {
			t.Fatalf("Check: %v", err)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		object, _ := objectWithFunctions(t, coff.MachineAMD64, []byte{0xc3}, map[string]uint32{"root": 0})
		ctx, cancel := context.WithCancel(context.Background())
		decoder := &testDisassembler{disassemble: func(ctx context.Context, _ []byte, _ uint64) ([]x86.Instruction, error) {
			cancel()
			return nil, ctx.Err()
		}}
		_, err := BuildGraph(ctx, object, Options{Disassembler: decoder})
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnproven) {
			t.Fatalf("error = %v", err)
		}
		if decoder.closeCount != 0 {
			t.Fatalf("caller-owned decoder closed %d times", decoder.closeCount)
		}
	})

	t.Run("factory ownership", func(t *testing.T) {
		object, _ := objectWithFunctions(t, coff.MachineI386, []byte{0xc3}, map[string]uint32{"_root": 0})
		decoder := fixedDecoder([]byte{0xc3}, "ret")
		graph, err := BuildGraph(context.Background(), object, Options{Factory: func(_ context.Context, mode x86.Mode) (x86.Disassembler, error) {
			if mode != x86.Mode32 {
				t.Fatalf("mode = %v", mode)
			}
			return decoder, nil
		}})
		if err != nil {
			t.Fatalf("BuildGraph: %v", err)
		}
		if decoder.closeCount != 1 {
			t.Fatalf("factory decoder close count = %d", decoder.closeCount)
		}
		if _, err := graph.Check(context.Background(), ""); !errors.Is(err, ErrUnproven) {
			t.Fatalf("empty root error = %v", err)
		}
		if _, err := graph.Check(context.Background()); !errors.Is(err, ErrUnproven) {
			t.Fatalf("no root error = %v", err)
		}
		if _, err := (*Graph)(nil).Check(context.Background(), "_root"); !errors.Is(err, ErrUnproven) {
			t.Fatalf("nil graph error = %v", err)
		}
	})

	t.Run("both decoder options", func(t *testing.T) {
		object, _ := objectWithFunctions(t, coff.MachineAMD64, []byte{0xc3}, map[string]uint32{"root": 0})
		decoder := fixedDecoder([]byte{0xc3}, "ret")
		_, err := BuildGraph(context.Background(), object, Options{
			Disassembler: decoder,
			Factory:      func(context.Context, x86.Mode) (x86.Disassembler, error) { return decoder, nil },
		})
		if !errors.Is(err, ErrUnproven) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestGraphConcurrentChecks(t *testing.T) {
	code := slotCode(3)
	putCall(code, 0, 8)
	putCall(code, 8, 0)
	object, _ := objectWithFunctions(t, coff.MachineAMD64, code, map[string]uint32{"root": 0, "cycle": 8, "other": 16})
	graph, err := BuildGraph(context.Background(), object, decoderOptions(coff.MachineAMD64))
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	var wait sync.WaitGroup
	errorsOut := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 25; iteration++ {
				report, err := graph.Check(context.Background(), "root", "other")
				if err != nil {
					errorsOut <- err
					return
				}
				if len(report.Visited) != 3 || len(graph.Functions()) != 3 || len(graph.Edges()) != 2 {
					errorsOut <- errors.New("inconsistent concurrent result")
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

type testDisassembler struct {
	disassemble func(context.Context, []byte, uint64) ([]x86.Instruction, error)
	closeCount  int
}

func (d *testDisassembler) Disassemble(ctx context.Context, code []byte, address uint64) ([]x86.Instruction, error) {
	return d.disassemble(ctx, code, address)
}

func (d *testDisassembler) Close(context.Context) error {
	d.closeCount++
	return nil
}

func fixedDecoder(code []byte, mnemonic string) *testDisassembler {
	return &testDisassembler{disassemble: func(context.Context, []byte, uint64) ([]x86.Instruction, error) {
		return []x86.Instruction{{Address: 0, Bytes: append([]byte(nil), code...), Mnemonic: mnemonic}}, nil
	}}
}

func objectWithFunctions(t *testing.T, machine coff.Machine, code []byte, functions map[string]uint32) (*coff.Object, *coff.Section) {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", code)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(functions))
	for name := range functions {
		names = append(names, name)
	}
	// Deliberately reverse lexical order often enough to prove graph order is
	// based on addresses, not map or symbol insertion order.
	for left, right := 0, len(names)-1; left < right; left, right = left+1, right-1 {
		names[left], names[right] = names[right], names[left]
	}
	for _, name := range names {
		if err := object.AddSymbol(coff.NewFunctionSymbol(text, name, functions[name])); err != nil {
			t.Fatal(err)
		}
	}
	return object, text
}

func slotCode(slots int) []byte {
	code := make([]byte, slots*8)
	for index := range code {
		code[index] = 0x90
	}
	for slot := 0; slot < slots; slot++ {
		code[slot*8] = 0xc3
	}
	return code
}

func putCall(code []byte, from, target int) {
	code[from] = 0xe8
	displacement := int32(target - (from + 5))
	code[from+1] = byte(displacement)
	code[from+2] = byte(displacement >> 8)
	code[from+3] = byte(displacement >> 16)
	code[from+4] = byte(displacement >> 24)
	code[from+5] = 0xc3
}

func findSymbol(t *testing.T, object *coff.Object, name string) *coff.Symbol {
	t.Helper()
	for _, symbol := range object.Symbols {
		if symbol.Name == name {
			return symbol
		}
	}
	t.Fatalf("symbol %q not found", name)
	return nil
}

func rootFor(machine coff.Machine) string {
	if machine == coff.MachineI386 {
		return "_root"
	}
	return "root"
}
