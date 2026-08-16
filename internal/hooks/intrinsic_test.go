// SPDX-License-Identifier: GPL-3.0-only

package hooks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	crystalhash "github.com/sliverarmory/crystal-grotto/internal/hash"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestIntrinsicArchitectureValidationAndOverwrite(t *testing.T) {
	x64 := hookTestObject(t, coff.MachineAMD64, "wrapper")
	model := mustNewModel(t, x64)
	if _, err := applyCommand(context.Background(), model, x64, "intrinsic", []string{"bad", "$CODE"}, func(string) ([]byte, error) {
		return []byte{1}, nil
	}); err == nil || err.Error() != "Intrinsic symbol bad must start with __" {
		t.Fatalf("x64 prefix error = %v", err)
	}
	called := false
	if _, err := applyCommand(context.Background(), model, x64, "intrinsic", []string{"bad", "$CODE"}, func(string) ([]byte, error) {
		called = true
		return nil, nil
	}); err == nil || called {
		t.Fatalf("resolver ran before prefix validation: called=%v err=%v", called, err)
	}
	model = mustApply(t, model, x64, "intrinsic", []string{"__custom", "$CODE"}, func(reference string) ([]byte, error) {
		if reference != "$CODE" {
			t.Fatalf("reference = %q", reference)
		}
		return []byte{1, 2}, nil
	})
	model = mustApply(t, model, x64, "intrinsic", []string{"__custom", "$NEXT"}, func(string) ([]byte, error) {
		return []byte{3, 4, 5}, nil
	})
	if snapshot := model.Snapshot().Intrinsics; len(snapshot) != 1 || !bytes.Equal(snapshot[0].Content, []byte{3, 4, 5}) {
		t.Fatalf("intrinsic overwrite = %#v", snapshot)
	}

	x86 := hookTestObject(t, coff.MachineI386, "_wrapper")
	x86Model := mustNewModel(t, x86)
	if _, err := applyCommand(context.Background(), x86Model, x86, "intrinsic", []string{"__wrong", "$CODE"}, func(string) ([]byte, error) {
		return nil, nil
	}); err == nil || err.Error() != "Intrinsic symbol __wrong must start with ___" {
		t.Fatalf("x86 prefix error = %v", err)
	}
	if _, err := applyCommand(context.Background(), x86Model, x86, "intrinsic", []string{"___valid", "$CODE"}, func(string) ([]byte, error) {
		return nil, nil
	}); err != nil {
		t.Fatalf("x86 intrinsic: %v", err)
	}
}

func TestResolveROR13NamedAndTagIntrinsics(t *testing.T) {
	call := x86.Instruction{Bytes: []byte{0xe8, 0, 0, 0, 0}, Mnemonic: "call", Operands: "0"}
	tests := []struct {
		symbol string
		want   uint32
	}{
		{"__ror13_LoadLibraryA", 0xec0e4e8e},
		{"___djb2_hello", 0x0f923099},
		{"__tag_value", crystalhash.ROR13{}.Sum32([]byte("__tag_value"))},
		{"___tag_value", crystalhash.ROR13{}.Sum32([]byte("___tag_value"))},
	}
	for _, test := range tests {
		expansion, matched, err := ResolveROR13(CallSite{HasRelocation: true, Symbol: test.symbol, Instruction: call})
		if err != nil || !matched {
			t.Fatalf("ResolveROR13(%q) = %#v,%v,%v", test.symbol, expansion, matched, err)
		}
		if expansion.Kind != ExpansionHashImmediate || expansion.Immediate != test.want || !expansion.ResolvesRelocation || expansion.RequiresRebuild || expansion.RequiresEncoder {
			t.Fatalf("expansion = %#v", expansion)
		}
		if len(expansion.Bytes) != 5 || expansion.Bytes[0] != 0xb8 || binary.LittleEndian.Uint32(expansion.Bytes[1:]) != test.want {
			t.Fatalf("encoded expansion = %x", expansion.Bytes)
		}
	}
	if _, matched, err := ResolveROR13(CallSite{HasRelocation: false, Symbol: "__ror13_X", Instruction: call}); matched || err != nil {
		t.Fatalf("site without relocation = matched %v, %v", matched, err)
	}
	if _, matched, err := ResolveROR13(CallSite{HasRelocation: true, Symbol: "ordinary", Instruction: call}); matched || err != nil {
		t.Fatalf("ordinary site = matched %v, %v", matched, err)
	}
	bad := CallSite{
		HasRelocation: true, Symbol: "__ror13_X",
		Instruction:       x86.Instruction{Bytes: []byte{0xff, 0xd0}, Form: "CALL r/m64"},
		InstructionString: "0000 call rax",
	}
	if _, matched, err := ResolveROR13(bad); !matched || err == nil || !strings.Contains(err.Error(), "Can't expand linker intrinsic __ror13_X for 0000 call rax") {
		t.Fatalf("bad form = matched %v, error %v", matched, err)
	}
}

func TestResolveUserIntrinsicsAndPassPrecedence(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "wrapper")
	model := mustNewModel(t, object)
	for symbol, content := range map[string][]byte{
		"__custom":             {0x90, 0x90},
		"__ror13_LoadLibraryA": {0xcc},
		"__resolve_hook":       {0xcc},
	} {
		model = mustApply(t, model, object, "intrinsic", []string{symbol, "$CODE"}, func(string) ([]byte, error) {
			return content, nil
		})
	}
	call := x86.Instruction{Bytes: []byte{0xe8, 0, 0, 0, 0}, Mnemonic: "call"}
	expansion, matched, err := model.ResolveIntrinsic(CallSite{HasRelocation: true, Symbol: "__custom", Instruction: call})
	if err != nil || !matched || expansion.Kind != ExpansionUserBytes || !bytes.Equal(expansion.Bytes, []byte{0x90, 0x90}) || !expansion.RequiresRebuild {
		t.Fatalf("user expansion = %#v,%v,%v", expansion, matched, err)
	}
	if expansion.EncodingError() != nil {
		t.Fatalf("raw user bytes unexpectedly require an encoder: %v", expansion.EncodingError())
	}
	expansion.Bytes[0] = 0xff
	stored, _ := model.UserIntrinsics().Lookup("__custom")
	if !bytes.Equal(stored, []byte{0x90, 0x90}) {
		t.Fatalf("expansion exposed stored bytes: %x", stored)
	}

	expansion, matched, err = model.ResolveIntrinsic(CallSite{HasRelocation: true, Symbol: "__ror13_LoadLibraryA", Instruction: call})
	if err != nil || !matched || expansion.Kind != ExpansionHashImmediate {
		t.Fatalf("built-in did not precede user intrinsic: %#v,%v,%v", expansion, matched, err)
	}
	expansion, matched, err = model.ResolveIntrinsic(CallSite{HasRelocation: true, Symbol: "__resolve_hook", Instruction: call})
	if err != nil || !matched || expansion.Kind != ExpansionResolveHooks || !expansion.RequiresEncoder || !errors.Is(expansion.EncodingError(), ErrEncoderRequired) {
		t.Fatalf("resolve-hook expansion = %#v,%v,%v", expansion, matched, err)
	}

	bad := CallSite{
		HasRelocation: true, Symbol: "__custom",
		Instruction: x86.Instruction{Bytes: []byte{0xff, 0xd0}, Mnemonic: "call", Operands: "rax"},
	}
	if _, matched, err := model.ResolveIntrinsic(bad); !matched || err == nil || !strings.Contains(err.Error(), "Can't expand user-defined intrinsic") {
		t.Fatalf("bad user form = matched %v, error %v", matched, err)
	}
	if _, matched, err := model.ResolveIntrinsic(CallSite{Symbol: "__custom", Instruction: call}); matched || err != nil {
		t.Fatalf("no-relocation user intrinsic = matched %v, error %v", matched, err)
	}
	if _, matched, err := model.ResolveIntrinsic(CallSite{HasRelocation: true, Symbol: "__unknown", Instruction: call}); matched || err != nil {
		t.Fatalf("unknown intrinsic = matched %v, error %v", matched, err)
	}
}

func TestResolveHookIntrinsicUsesArchitectureSymbol(t *testing.T) {
	call := x86.Instruction{Bytes: []byte{0xe8, 0, 0, 0, 0}, Mnemonic: "call"}
	x86Object := hookTestObject(t, coff.MachineI386, "_wrapper")
	x86Model := mustNewModel(t, x86Object)
	if expansion, matched, err := x86Model.ResolveIntrinsic(CallSite{HasRelocation: true, Symbol: "___resolve_hook", Instruction: call}); err != nil || !matched || expansion.Kind != ExpansionResolveHooks {
		t.Fatalf("x86 resolve hook = %#v,%v,%v", expansion, matched, err)
	}
	if _, matched, err := x86Model.ResolveIntrinsic(CallSite{HasRelocation: true, Symbol: "__resolve_hook", Instruction: call}); err != nil || matched {
		t.Fatalf("x64 spelling matched x86 = %v,%v", matched, err)
	}
}

func TestUserIntrinsicsDefensiveDeterministicView(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "wrapper")
	model := mustNewModel(t, object)
	model = mustApply(t, model, object, "intrinsic", []string{"__z", "$Z"}, func(string) ([]byte, error) { return []byte{2}, nil })
	model = mustApply(t, model, object, "intrinsic", []string{"__a", "$A"}, func(string) ([]byte, error) { return []byte{1}, nil })
	view := model.UserIntrinsics()
	if got, want := view.Symbols(), []string{"__a", "__z"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Symbols = %#v, want %#v", got, want)
	}
	content, ok := view.Lookup("__a")
	if !ok || !bytes.Equal(content, []byte{1}) {
		t.Fatalf("Lookup = %x,%v", content, ok)
	}
	content[0] = 9
	again, _ := view.Lookup("__a")
	if !bytes.Equal(again, []byte{1}) {
		t.Fatal("Lookup exposed view storage")
	}
}

func FuzzResolveROR13NeverPanics(f *testing.F) {
	f.Add("__ror13_X", []byte{0xe8, 0, 0, 0, 0}, true)
	f.Add("__tag_x", []byte{0xff, 0xd0}, true)
	f.Add("", []byte{}, false)
	f.Fuzz(func(t *testing.T, symbol string, encoded []byte, relocation bool) {
		_, _, _ = ResolveROR13(CallSite{
			HasRelocation: relocation,
			Symbol:        symbol,
			Instruction:   x86.Instruction{Bytes: encoded},
		})
	})
}
