// SPDX-License-Identifier: GPL-3.0-only

package hookencode

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
	"github.com/sliverarmory/crystal-grotto/internal/hooks"
	"github.com/sliverarmory/crystal-grotto/internal/linker"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestApplyAttachExactVectors(t *testing.T) {
	tests := []struct {
		name             string
		machine          coff.Machine
		input            []byte
		functionOffset   uint32
		relocationOffset uint32
		relocationType   uint16
		want             []byte
		wantForm         Form
		wantSymbol       string
		wantType         uint16
		wantRelocation   bool
	}{
		{
			name: "x64 indirect call", machine: coff.MachineAMD64,
			input: []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3, 0xc3}, functionOffset: 7,
			relocationOffset: 2, relocationType: coff.RelAMD64Rel32,
			want: []byte{0x90, 0xe8, 1, 0, 0, 0, 0xc3, 0xc3}, wantForm: FormCallIndirect64,
		},
		{
			name: "x64 indirect jump", machine: coff.MachineAMD64,
			input: []byte{0xff, 0x25, 0, 0, 0, 0, 0xc3, 0xc3}, functionOffset: 7,
			relocationOffset: 2, relocationType: coff.RelAMD64Rel32,
			want: []byte{0x90, 0xe9, 1, 0, 0, 0, 0xc3, 0xc3}, wantForm: FormJumpIndirect64,
		},
		{
			name: "x64 imported address", machine: coff.MachineAMD64,
			input: []byte{0x4c, 0x8b, 0x15, 0, 0, 0, 0, 0xc3, 0xc3}, functionOffset: 8,
			relocationOffset: 3, relocationType: coff.RelAMD64Rel32,
			want: []byte{0x4c, 0x8d, 0x15, 1, 0, 0, 0, 0xc3, 0xc3}, wantForm: FormMoveIndirect64,
		},
		{
			name: "x86 indirect call", machine: coff.MachineI386,
			input: []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3, 0xc3}, functionOffset: 7,
			relocationOffset: 2, relocationType: coff.RelI386Dir32,
			want: []byte{0x90, 0xe8, 1, 0, 0, 0, 0xc3, 0xc3}, wantForm: FormCallIndirect32,
		},
		{
			name: "x86 eax address", machine: coff.MachineI386,
			input: []byte{0xa1, 0, 0, 0, 0, 0xc3, 0xc3}, functionOffset: 6,
			relocationOffset: 1, relocationType: coff.RelI386Dir32,
			want: []byte{0xb8, 6, 0, 0, 0, 0xc3, 0xc3}, wantForm: FormMoveEAXMoffs32,
			wantSymbol: ".text", wantType: coff.RelI386Dir32, wantRelocation: true,
		},
		{
			name: "x86 ecx address", machine: coff.MachineI386,
			input: []byte{0x8b, 0x0d, 0, 0, 0, 0, 0xc3, 0xc3}, functionOffset: 7,
			relocationOffset: 2, relocationType: coff.RelI386Dir32,
			want: []byte{0x90, 0xb9, 7, 0, 0, 0, 0xc3, 0xc3}, wantForm: FormMoveIndirect32,
			wantSymbol: ".text", wantType: coff.RelI386Dir32, wantRelocation: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object := makeObject(t, test.machine, test.input, functionAt{"caller", 0}, functionAt{"wrapper", test.functionOffset})
			addRelocation(t, object, test.relocationOffset, test.relocationType, "__imp_KERNEL32$Sleep", nil)
			model := makeModel(t, object)
			model = applyHook(t, model, object, "attach", []string{"KERNEL32$Sleep", "wrapper"}, nil)
			before := mustMarshal(t, object)

			result, plan, err := Apply(context.Background(), object, model)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if got := result.GetSection(".text").Data; !bytes.Equal(got, test.want) {
				t.Fatalf("text = % x, want % x", got, test.want)
			}
			if len(plan.Sites) != 1 || plan.Sites[0].Pass != PassAttach || plan.Sites[0].Form != test.wantForm || plan.Sites[0].Context != "caller" || plan.Sites[0].Wrapper != "wrapper" {
				t.Fatalf("plan = %#v", plan)
			}
			relocations := result.GetSection(".text").Relocations
			if !test.wantRelocation {
				if len(relocations) != 0 {
					t.Fatalf("resolved relocations = %#v", relocations)
				}
			} else {
				if len(relocations) != 1 {
					t.Fatalf("relocations = %#v", relocations)
				}
				relocation := relocations[0]
				if relocation.SymbolName != test.wantSymbol || relocation.Symbol == nil || relocation.Symbol.Name != test.wantSymbol || relocation.Type != test.wantType {
					t.Fatalf("relocation = %#v", relocation)
				}
			}
			if got := mustMarshal(t, object); !bytes.Equal(got, before) {
				t.Fatal("Apply mutated source object")
			}
		})
	}
}

func TestAttachUsesExternalDeclarationChain(t *testing.T) {
	data := []byte{
		0xff, 0x15, 0, 0, 0, 0,
		0xff, 0x15, 0, 0, 0, 0,
		0xff, 0x15, 0, 0, 0, 0,
		0xc3,
	}
	object := makeObject(t, coff.MachineAMD64, data,
		functionAt{"caller", 0}, functionAt{"wrap1", 6}, functionAt{"wrap2", 12})
	imported := &coff.Symbol{Name: "__imp_KERNEL32$Sleep", StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(imported); err != nil {
		t.Fatal(err)
	}
	text := object.GetSection(".text")
	for _, offset := range []uint32{2, 8, 14} {
		text.Relocations = append(text.Relocations, &coff.Relocation{
			Section: text, VirtualAddress: offset, SymbolName: imported.Name,
			Symbol: imported, Type: coff.RelAMD64Rel32,
		})
	}

	model := makeModel(t, object)
	model = applyHook(t, model, object, "attach", []string{"KERNEL32$Sleep", "wrap1"}, nil)
	model = applyHook(t, model, object, "attach", []string{"KERNEL32$Sleep", "wrap2"}, nil)
	result, plan, err := Apply(context.Background(), object, model)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x90, 0xe8, 0, 0, 0, 0,
		0x90, 0xe8, 0, 0, 0, 0,
		0xff, 0x15, 0, 0, 0, 0,
		0xc3,
	}
	if got := result.GetSection(".text").Data; !bytes.Equal(got, want) {
		t.Fatalf("text = % x, want % x", got, want)
	}
	if len(plan.Sites) != 2 || plan.Sites[0].Context != "caller" || plan.Sites[0].Wrapper != "wrap1" || plan.Sites[1].Context != "wrap1" || plan.Sites[1].Wrapper != "wrap2" {
		t.Fatalf("plan = %#v", plan)
	}
	if relocations := result.GetSection(".text").Relocations; len(relocations) != 1 || relocations[0].VirtualAddress != 14 || relocations[0].SymbolName != "__imp_KERNEL32$Sleep" {
		t.Fatalf("remaining relocations = %#v", relocations)
	}
}

func TestRedirectResolvedChainAndSelections(t *testing.T) {
	// caller -> target, wrap1 -> target, wrap2 -> target. Each function begins
	// at the next five-byte CALL; target is the final RET.
	input := []byte{
		0xe8, 10, 0, 0, 0,
		0xe8, 5, 0, 0, 0,
		0xe8, 0, 0, 0, 0,
		0xc3,
	}
	base := makeObject(t, coff.MachineAMD64, input,
		functionAt{"caller", 0}, functionAt{"wrap1", 5}, functionAt{"wrap2", 10}, functionAt{"target", 15})
	baseModel := makeModel(t, base)
	baseModel = applyHook(t, baseModel, base, "redirect", []string{"target", "wrap1"}, nil)
	baseModel = applyHook(t, baseModel, base, "redirect", []string{"target", "wrap2"}, nil)

	tests := []struct {
		name       string
		configure  func(*hooks.Model) *hooks.Model
		wantCalls  []byte
		wantRoutes [][3]string
	}{
		{
			name:       "declaration chain",
			configure:  func(model *hooks.Model) *hooks.Model { return model },
			wantCalls:  []byte{0, 0, 0},
			wantRoutes: [][3]string{{"caller", "target", "wrap1"}, {"wrap1", "target", "wrap2"}},
		},
		{
			name: "caller opts out of first wrapper",
			configure: func(model *hooks.Model) *hooks.Model {
				return applyHook(t, model, base, "optout", []string{"caller", "wrap1"}, nil)
			},
			wantCalls:  []byte{5, 0, 0},
			wantRoutes: [][3]string{{"caller", "target", "wrap2"}, {"wrap1", "target", "wrap2"}},
		},
		{
			name: "caller preserves target",
			configure: func(model *hooks.Model) *hooks.Model {
				return applyHook(t, model, base, "preserve", []string{"target", "caller"}, nil)
			},
			wantCalls:  []byte{10, 0, 0},
			wantRoutes: [][3]string{{"wrap1", "target", "wrap2"}},
		},
		{
			name: "caller is protected",
			configure: func(model *hooks.Model) *hooks.Model {
				return applyHook(t, model, base, "protect", []string{"caller"}, nil)
			},
			wantCalls:  []byte{10, 0, 0},
			wantRoutes: [][3]string{{"wrap1", "target", "wrap2"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, plan, err := Apply(context.Background(), base, test.configure(baseModel))
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			text := result.GetSection(".text").Data
			gotCalls := []byte{text[1], text[6], text[11]}
			if !bytes.Equal(gotCalls, test.wantCalls) {
				t.Fatalf("call displacements = %v, want %v", gotCalls, test.wantCalls)
			}
			if len(plan.Sites) != len(test.wantRoutes) {
				t.Fatalf("plan sites = %#v", plan.Sites)
			}
			for index, want := range test.wantRoutes {
				got := plan.Sites[index]
				if got.Pass != PassRedirect || got.Context != want[0] || got.Target != want[1] || got.Wrapper != want[2] || got.RelocationIndex != -1 {
					t.Fatalf("site %d = %#v, want route %v", index, got, want)
				}
			}
		})
	}
}

func TestRedirectX86RelocationBackedAddress(t *testing.T) {
	data := []byte{0xb8, 7, 0, 0, 0, 0xc3, 0xc3, 0xc3}
	object := makeObject(t, coff.MachineI386, data,
		functionAt{"caller", 0}, functionAt{"wrapper", 6}, functionAt{"target", 7})
	text := object.GetSection(".text")
	addRelocation(t, object, 1, coff.RelI386Dir32, ".text", object.GetSymbol(".text"))
	model := makeModel(t, object)
	model = applyHook(t, model, object, "redirect", []string{"target", "wrapper"}, nil)

	result, plan, err := Apply(context.Background(), object, model)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(plan.Sites) != 1 || plan.Sites[0].Form != FormMoveImmediate32 || plan.Sites[0].RelocationIndex != 0 {
		t.Fatalf("plan = %#v", plan)
	}
	gotText := result.GetSection(".text")
	if got := binary.LittleEndian.Uint32(gotText.Data[1:5]); got != 6 {
		t.Fatalf("redirected address = %d, want 6", got)
	}
	if gotText.Relocations[0].SymbolName != ".text" || gotText.Relocations[0].Type != coff.RelI386Dir32 {
		t.Fatalf("relocation = %#v", gotText.Relocations[0])
	}
	if binary.LittleEndian.Uint32(text.Data[1:5]) != 7 {
		t.Fatal("source addend changed")
	}
}

func TestRedirectRelocationBackedCallJumpAndMoveVectors(t *testing.T) {
	t.Run("x64 section relative", func(t *testing.T) {
		data := []byte{
			0xe8, 26, 0, 0, 0,
			0xe9, 26, 0, 0, 0,
			0x48, 0x8d, 0x05, 26, 0, 0, 0,
			0x48, 0x8b, 0x0d, 26, 0, 0, 0,
			0xc3, 0xc3, 0xc3,
		}
		object := makeObject(t, coff.MachineAMD64, data,
			functionAt{"caller", 0}, functionAt{"wrapper", 25}, functionAt{"target", 26})
		sectionSymbol := object.GetSymbol(".text")
		for _, offset := range []uint32{1, 6, 13, 20} {
			addRelocation(t, object, offset, coff.RelAMD64Rel32, ".text", sectionSymbol)
		}
		model := makeModel(t, object)
		model = applyHook(t, model, object, "redirect", []string{"target", "wrapper"}, nil)
		result, plan, err := Apply(context.Background(), object, model)
		if err != nil {
			t.Fatal(err)
		}
		want := append([]byte(nil), data...)
		for offset, delta := range map[int]uint32{1: 20, 6: 15, 13: 8, 20: 1} {
			binary.LittleEndian.PutUint32(want[offset:offset+4], delta)
		}
		if got := result.GetSection(".text").Data; !bytes.Equal(got, want) {
			t.Fatalf("text = % x, want % x", got, want)
		}
		if len(result.GetSection(".text").Relocations) != 0 {
			t.Fatalf("resolved relocations = %#v", result.GetSection(".text").Relocations)
		}
		wantForms := []Form{FormCallRel32, FormJumpRel32, FormLEA64, FormMoveIndirect64}
		if len(plan.Sites) != len(wantForms) {
			t.Fatalf("plan = %#v", plan)
		}
		for index, wantForm := range wantForms {
			if plan.Sites[index].Form != wantForm || plan.Sites[index].Wrapper != "wrapper" {
				t.Fatalf("site %d = %#v", index, plan.Sites[index])
			}
		}
	})

	t.Run("x86 symbol relative", func(t *testing.T) {
		data := []byte{0xe8, 0, 0, 0, 0, 0xe9, 0, 0, 0, 0, 0xc3, 0xc3, 0xc3}
		object := makeObject(t, coff.MachineI386, data,
			functionAt{"caller", 0}, functionAt{"wrapper", 11}, functionAt{"target", 12})
		target := object.GetSymbol("target")
		addRelocation(t, object, 1, coff.RelI386Rel32, target.Name, target)
		addRelocation(t, object, 6, coff.RelI386Rel32, target.Name, target)
		model := makeModel(t, object)
		model = applyHook(t, model, object, "redirect", []string{"target", "wrapper"}, nil)
		result, plan, err := Apply(context.Background(), object, model)
		if err != nil {
			t.Fatal(err)
		}
		want := append([]byte(nil), data...)
		binary.LittleEndian.PutUint32(want[1:5], 6)
		binary.LittleEndian.PutUint32(want[6:10], 1)
		if got := result.GetSection(".text").Data; !bytes.Equal(got, want) {
			t.Fatalf("text = % x, want % x", got, want)
		}
		if len(result.GetSection(".text").Relocations) != 0 || len(plan.Sites) != 2 {
			t.Fatalf("relocations/plan = %#v / %#v", result.GetSection(".text").Relocations, plan)
		}
	})
}

func TestRedirectResolvedX64LEA(t *testing.T) {
	object := makeObject(t, coff.MachineAMD64,
		[]byte{0x48, 0x8d, 0x05, 1, 0, 0, 0, 0xc3, 0xc3},
		functionAt{"caller", 0}, functionAt{"wrapper", 7}, functionAt{"target", 8})
	model := makeModel(t, object)
	model = applyHook(t, model, object, "redirect", []string{"target", "wrapper"}, nil)
	result, plan, err := Apply(context.Background(), object, model)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3, 0xc3}
	if got := result.GetSection(".text").Data; !bytes.Equal(got, want) {
		t.Fatalf("text = % x, want % x", got, want)
	}
	if len(plan.Sites) != 1 || plan.Sites[0].Form != FormLEA64 || plan.Sites[0].RelocationIndex != -1 {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestIntrinsicPassAndTypedBoundaries(t *testing.T) {
	t.Run("same length user bytes", func(t *testing.T) {
		object := makeObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, functionAt{"caller", 0})
		addRelocation(t, object, 1, coff.RelAMD64Rel32, "__custom", nil)
		model := makeModel(t, object)
		model = applyHook(t, model, object, "intrinsic", []string{"__custom", "$CODE"}, []byte{0x90, 0xcc, 0x90, 0xcc, 0x90})
		result, plan, err := Apply(context.Background(), object, model)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := result.GetSection(".text").Data, []byte{0x90, 0xcc, 0x90, 0xcc, 0x90, 0xc3}; !bytes.Equal(got, want) {
			t.Fatalf("text = % x, want % x", got, want)
		}
		if len(result.GetSection(".text").Relocations) != 0 || len(plan.Sites) != 1 || plan.Sites[0].Pass != PassIntrinsic {
			t.Fatalf("result relocations/plan = %#v / %#v", result.GetSection(".text").Relocations, plan)
		}
	})

	t.Run("built in hash precedes user bytes", func(t *testing.T) {
		object := makeObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, functionAt{"caller", 0})
		addRelocation(t, object, 1, coff.RelAMD64Rel32, "__ror13_LoadLibraryA", nil)
		model := makeModel(t, object)
		model = applyHook(t, model, object, "intrinsic", []string{"__ror13_LoadLibraryA", "$CODE"}, []byte{0xcc, 0xcc, 0xcc, 0xcc, 0xcc})
		result, _, err := Apply(context.Background(), object, model)
		if err != nil {
			t.Fatal(err)
		}
		got := result.GetSection(".text").Data[:5]
		if got[0] != 0xb8 || binary.LittleEndian.Uint32(got[1:]) != 0xec0e4e8e {
			t.Fatalf("hash expansion = % x", got)
		}
	})

	t.Run("length change", func(t *testing.T) {
		object := makeObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, functionAt{"caller", 0})
		addRelocation(t, object, 1, coff.RelAMD64Rel32, "__custom", nil)
		model := makeModel(t, object)
		model = applyHook(t, model, object, "intrinsic", []string{"__custom", "$CODE"}, []byte{0x90})
		before := mustMarshal(t, object)
		if result, _, err := Apply(context.Background(), object, model); result != nil || !errors.Is(err, ErrRebuildRequired) {
			t.Fatalf("Apply = %#v, %v", result, err)
		}
		if !bytes.Equal(mustMarshal(t, object), before) {
			t.Fatal("failed Apply mutated source")
		}
	})

	t.Run("resolve hook", func(t *testing.T) {
		object := makeObject(t, coff.MachineAMD64, []byte{0xe8, 0, 0, 0, 0, 0xc3}, functionAt{"caller", 0})
		addRelocation(t, object, 1, coff.RelAMD64Rel32, "__resolve_hook", nil)
		model := makeModel(t, object)
		if _, _, err := Apply(context.Background(), object, model); !errors.Is(err, ErrResolveHook) || !errors.Is(err, hooks.ErrEncoderRequired) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestAttachRoundTripAndLinkResolution(t *testing.T) {
	object := makeObject(t, coff.MachineAMD64,
		[]byte{0xff, 0x15, 0, 0, 0, 0, 0xc3, 0xc3},
		functionAt{"caller", 0}, functionAt{"wrapper", 7})
	addRelocation(t, object, 2, coff.RelAMD64Rel32, "__imp_KERNEL32$Sleep", nil)
	model := makeModel(t, object)
	model = applyHook(t, model, object, "attach", []string{"KERNEL32$Sleep", "wrapper"}, nil)
	result, _, err := Apply(context.Background(), object, model)
	if err != nil {
		t.Fatal(err)
	}
	raw := mustMarshal(t, result)
	parsed, err := coff.Parse(raw)
	if err != nil {
		t.Fatalf("Parse(Marshal(result)): %v", err)
	}
	linked, err := linker.Merge(parsed)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	want := []byte{0x90, 0xe8, 1, 0, 0, 0, 0xc3, 0xc3}
	if got := linked.GetSection(".text").Data; !bytes.Equal(got, want) {
		t.Fatalf("linked text = % x, want % x", got, want)
	}
	if len(linked.GetSection(".text").Relocations) != 0 {
		t.Fatalf("linked relocations = %#v", linked.GetSection(".text").Relocations)
	}
}

func TestTypedErrorsCancellationAndTransactionality(t *testing.T) {
	object := makeObject(t, coff.MachineAMD64,
		[]byte{0x48, 0x03, 0x05, 0, 0, 0, 0, 0xc3, 0xc3},
		functionAt{"caller", 0}, functionAt{"wrapper", 8})
	addRelocation(t, object, 3, coff.RelAMD64Rel32, "__imp_KERNEL32$Sleep", nil)
	model := makeModel(t, object)
	model = applyHook(t, model, object, "attach", []string{"KERNEL32$Sleep", "wrapper"}, nil)
	before := mustMarshal(t, object)
	if result, _, err := Apply(context.Background(), object, model); result != nil || !errors.Is(err, ErrUnsupportedForm) {
		t.Fatalf("unsupported Apply = %#v, %v", result, err)
	}
	if !bytes.Equal(mustMarshal(t, object), before) {
		t.Fatal("unsupported Apply mutated source")
	}
	if _, _, err := Apply(nil, object, model); !errors.Is(err, ErrNilContext) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, _, err := Apply(context.Background(), nil, model); !errors.Is(err, ErrNilObject) {
		t.Fatalf("nil object error = %v", err)
	}
	if _, _, err := Apply(context.Background(), object, nil); !errors.Is(err, ErrNilModel) {
		t.Fatalf("nil model error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Apply(canceled, object, model); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
	arm, _ := coff.NewObject(coff.MachineARM64)
	armModelObject := makeObject(t, coff.MachineAMD64, []byte{0xc3}, functionAt{"caller", 0})
	if _, err := BuildPlan(context.Background(), arm, makeModel(t, armModelObject)); !errors.Is(err, ErrUnsupportedMachine) {
		t.Fatalf("ARM error = %v", err)
	}
}

func TestOverlappingMatchedRelocationsAreRejected(t *testing.T) {
	object := makeObject(t, coff.MachineAMD64,
		[]byte{0xff, 0x15, 0, 0, 0, 0, 0xc3, 0xc3},
		functionAt{"caller", 0}, functionAt{"wrapper", 7})
	imported := &coff.Symbol{Name: "__imp_KERNEL32$Sleep", StorageClass: coff.SymbolClassExternal}
	if err := object.AddSymbol(imported); err != nil {
		t.Fatal(err)
	}
	text := object.GetSection(".text")
	for range 2 {
		text.Relocations = append(text.Relocations, &coff.Relocation{
			Section: text, VirtualAddress: 2, SymbolName: imported.Name,
			Symbol: imported, Type: coff.RelAMD64Rel32,
		})
	}
	model := makeModel(t, object)
	model = applyHook(t, model, object, "attach", []string{"KERNEL32$Sleep", "wrapper"}, nil)
	if _, err := BuildPlan(context.Background(), object, model); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("error = %v", err)
	}
}

func TestRedirectRel8OutOfRangeIsTyped(t *testing.T) {
	data := bytes.Repeat([]byte{0x90}, 202)
	data[0], data[1] = 0xeb, 126 // target at 128
	data[128] = 0xc3
	data[200] = 0xc3
	object := makeObject(t, coff.MachineAMD64, data,
		functionAt{"caller", 0}, functionAt{"target", 128}, functionAt{"wrapper", 200})
	model := makeModel(t, object)
	model = applyHook(t, model, object, "redirect", []string{"target", "wrapper"}, nil)
	if _, _, err := Apply(context.Background(), object, model); !errors.Is(err, ErrBranchRange) {
		t.Fatalf("error = %v", err)
	}
}

func TestConcurrentApplyDeterministic(t *testing.T) {
	object := makeObject(t, coff.MachineAMD64,
		[]byte{0xff, 0x15, 0, 0, 0, 0, 0xc3, 0xc3},
		functionAt{"caller", 0}, functionAt{"wrapper", 7})
	addRelocation(t, object, 2, coff.RelAMD64Rel32, "__imp_KERNEL32$Sleep", nil)
	model := makeModel(t, object)
	model = applyHook(t, model, object, "attach", []string{"KERNEL32$Sleep", "wrapper"}, nil)

	const workers = 4
	results := make(chan []byte, workers)
	errorsOut := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, plan, err := Apply(context.Background(), object, model)
			if err != nil {
				errorsOut <- err
				return
			}
			if len(plan.Sites) != 1 {
				errorsOut <- fmt.Errorf("sites = %d", len(plan.Sites))
				return
			}
			encoded, err := coffwrite.Marshal(result)
			if err != nil {
				errorsOut <- err
				return
			}
			results <- encoded
		}()
	}
	wait.Wait()
	close(results)
	close(errorsOut)
	for err := range errorsOut {
		t.Errorf("concurrent Apply: %v", err)
	}
	var first []byte
	for result := range results {
		if first == nil {
			first = result
			continue
		}
		if !bytes.Equal(first, result) {
			t.Fatal("concurrent results differ")
		}
	}
}

func FuzzClassifiersNeverPanic(f *testing.F) {
	f.Add([]byte{0xe8, 0, 0, 0, 0}, uint8(1), true)
	f.Add([]byte{0x48, 0x8d, 0x05, 0, 0, 0, 0}, uint8(3), false)
	f.Add([]byte{0xff}, uint8(255), true)
	f.Fuzz(func(t *testing.T, encoded []byte, relocationOffset uint8, x86Mode bool) {
		machine := coff.MachineAMD64
		if x86Mode {
			machine = coff.MachineI386
		}
		instruction := x86.Instruction{Address: 7, Bytes: append([]byte(nil), encoded...)}
		_, _, operandOffset, operandWidth, recognized := classifyResolvedLocal(machine, instruction)
		if recognized {
			_, _ = retargetRelative(instruction.Bytes, operandOffset, operandWidth, instruction.Address, 42)
		}
		_ = isCallRel32(encoded, int(relocationOffset))
		_ = isRIPMove64(encoded, int(relocationOffset))
		_ = isRIPLEA64(encoded, int(relocationOffset))
		_ = isAbsoluteMove32(encoded, int(relocationOffset))
	})
}

type functionAt struct {
	name   string
	offset uint32
}

func makeObject(t *testing.T, machine coff.Machine, data []byte, functions ...functionAt) *coff.Object {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", data)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	for _, function := range functions {
		if int(function.offset) >= len(data) {
			t.Fatalf("function %s offset %d exceeds %d-byte text", function.name, function.offset, len(data))
		}
		if err := object.AddSymbol(coff.NewFunctionSymbol(text, function.name, function.offset)); err != nil {
			t.Fatal(err)
		}
	}
	return object
}

func addRelocation(t *testing.T, object *coff.Object, offset uint32, relocationType uint16, name string, target *coff.Symbol) {
	t.Helper()
	if target == nil {
		target = &coff.Symbol{Name: name, StorageClass: coff.SymbolClassExternal}
		if err := object.AddSymbol(target); err != nil {
			t.Fatal(err)
		}
	}
	text := object.GetSection(".text")
	text.Relocations = append(text.Relocations, &coff.Relocation{
		Section: text, VirtualAddress: offset, SymbolName: name, Symbol: target, Type: relocationType,
	})
}

func makeModel(t *testing.T, object *coff.Object) *hooks.Model {
	t.Helper()
	model, err := hooks.New(object)
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func applyHook(t *testing.T, model *hooks.Model, object *coff.Object, command string, arguments []string, content []byte) *hooks.Model {
	t.Helper()
	directive, err := hooks.Parse(command, arguments)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := model.ApplyResolved(context.Background(), object, directive, content)
	if err != nil {
		t.Fatalf("apply %s: %v", command, err)
	}
	return updated
}

func mustMarshal(t *testing.T, object *coff.Object) []byte {
	t.Helper()
	encoded, err := coffwrite.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestPlanIsDefensive(t *testing.T) {
	object := makeObject(t, coff.MachineAMD64,
		[]byte{0xff, 0x15, 0, 0, 0, 0, 0xc3, 0xc3},
		functionAt{"caller", 0}, functionAt{"wrapper", 7})
	addRelocation(t, object, 2, coff.RelAMD64Rel32, "__imp_KERNEL32$Sleep", nil)
	model := makeModel(t, object)
	model = applyHook(t, model, object, "attach", []string{"KERNEL32$Sleep", "wrapper"}, nil)
	first, err := BuildPlan(context.Background(), object, model)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPlan(context.Background(), object, model)
	if err != nil {
		t.Fatal(err)
	}
	first.Sites[0].Original[0] ^= 0xff
	first.Sites[0].Replacement[0] ^= 0xff
	if reflect.DeepEqual(first, second) || second.Sites[0].Original[0] != 0xff || second.Sites[0].Replacement[0] != 0x90 {
		t.Fatalf("plans alias or changed unexpectedly: %#v %#v", first, second)
	}
}
