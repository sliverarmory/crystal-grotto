// SPDX-License-Identifier: GPL-3.0-only

package rulegen

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/spec"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

type testDisassembler struct {
	decode   func(context.Context, []byte, uint64) ([]x86.Instruction, error)
	closeErr error
	closed   atomic.Bool
}

func (d *testDisassembler) Disassemble(ctx context.Context, code []byte, address uint64) ([]x86.Instruction, error) {
	if d.decode != nil {
		return d.decode(ctx, code, address)
	}
	return decodeTestInstructions(ctx, code, address)
}

func (d *testDisassembler) Close(context.Context) error {
	d.closed.Store(true)
	return d.closeErr
}

func testFactory(modeSeen *x86.Mode) DisassemblerFactory {
	return func(_ context.Context, mode x86.Mode) (x86.Disassembler, error) {
		if modeSeen != nil {
			*modeSeen = mode
		}
		return &testDisassembler{}, nil
	}
}

func fixedOptions(factory DisassemblerFactory) GenerateOptions {
	return GenerateOptions{
		NewDisassembler: factory,
		UUID: func() (string, error) {
			return "12345678-1234-4234-8234-123456789abc", nil
		},
		Clock: func() time.Time {
			return time.Date(2025, time.January, 2, 0, 0, 0, 0, time.UTC)
		},
	}
}

func generateArgs() Args {
	return Args{MaxRules: 10, Agreement: 1, MinLength: 3, MaxLength: 16}
}

func TestGenerateX86AndX64Wildcards(t *testing.T) {
	tests := []struct {
		name       string
		machine    coff.Machine
		mode       x86.Mode
		code       []byte
		relocation uint32
		relocType  uint16
		wantBytes  string
	}{
		{
			name: "x86", machine: coff.MachineI386, mode: x86.Mode32,
			code:       []byte{0xeb, 0x0c, 0xb8, 0x11, 0x22, 0x33, 0x44, 0xe8, 1, 0, 0, 0, 0x31, 0xc0, 0xc3},
			relocation: 3, relocType: coff.RelI386Dir32,
			wantBytes: "B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0",
		},
		{
			name: "x64", machine: coff.MachineAMD64, mode: x86.Mode64,
			code:       []byte{0xeb, 0x0e, 0x48, 0x8b, 0x05, 0x11, 0x22, 0x33, 0x44, 0xe8, 1, 0, 0, 0, 0x31, 0xc0, 0xc3},
			relocation: 5, relocType: coff.RelAMD64Addr32NB,
			wantBytes: "48 8B 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			object, section := testObject(t, test.machine, test.code, map[string]uint32{"_entry": 0})
			section.Relocations = []*coff.Relocation{{
				Section: section, VirtualAddress: test.relocation, Type: test.relocType,
			}}
			var modeSeen x86.Mode
			result, err := Generate(context.Background(), object, spec.Metadata{Name: "Fixture"}, generateArgs(), fixedOptions(testFactory(&modeSeen)))
			if err != nil {
				t.Fatal(err)
			}
			if modeSeen != test.mode {
				t.Fatalf("factory mode = %s, want %s", modeSeen, test.mode)
			}
			if result.RuleName != "Fixture_12345678" || result.RuleCount != 1 || result.CandidateCount != 1 {
				t.Fatalf("unexpected result summary: %#v", result)
			}
			if !strings.Contains(string(result.YARA), "$r0_entry = { "+test.wantBytes+" }") {
				t.Fatalf("wildcard string missing from:\n%s", result.YARA)
			}
			if len(result.Functions) != 1 || result.Functions[0].Selected != 1 || result.Functions[0].Omitted != 2 {
				t.Fatalf("function result = %#v", result.Functions)
			}
			if countWarning(result.Warnings, WarningBoundaryDetail) != 2 {
				t.Fatalf("boundary warnings = %#v", result.Warnings)
			}
		})
	}
}

func TestGenerateWithDefaultCapstoneBackend(t *testing.T) {
	code := []byte{0xeb, 0x0e, 0x48, 0x8b, 0x05, 1, 2, 3, 4, 0xe8, 1, 0, 0, 0, 0x31, 0xc0, 0xc3}
	object, section := testObject(t, coff.MachineAMD64, code, map[string]uint32{"real_backend": 0})
	section.Relocations = []*coff.Relocation{{
		Section: section, VirtualAddress: 5, Type: coff.RelAMD64Addr32NB,
	}}
	options := fixedOptions(nil)
	result, err := Generate(context.Background(), object, spec.Metadata{Name: "Capstone"}, generateArgs(), options)
	if err != nil {
		t.Fatal(err)
	}
	if result.RuleCount != 1 || !strings.Contains(string(result.YARA), "48 8B 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0") {
		t.Fatalf("default Capstone result = %#v\n%s", result, result.YARA)
	}
}

func TestGenerateFiltersFunctionsAndLimitsRulesDeterministically(t *testing.T) {
	first := []byte{0xeb, 0x0e, 0x48, 0x8b, 0x05, 1, 2, 3, 4, 0xe8, 1, 0, 0, 0, 0x31, 0xc0, 0xc3}
	second := []byte{0xeb, 0x0e, 0x48, 0x8b, 0x05, 5, 6, 7, 8, 0xe8, 2, 0, 0, 0, 0x31, 0xc9, 0xc3}
	object, _ := testObject(t, coff.MachineAMD64, append(append([]byte(nil), first...), second...), map[string]uint32{
		"first": 0, "second": uint32(len(first)),
	})
	args := generateArgs()
	args.MaxRules = 1
	result, err := Generate(context.Background(), object, spec.Metadata{Name: "Limit"}, args, fixedOptions(testFactory(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if result.CandidateCount != 2 || result.RuleCount != 1 || len(result.Functions) != 2 {
		t.Fatalf("unexpected limit summary: %#v", result)
	}
	if result.Functions[0].Selected != 1 || result.Functions[1].Selected != 0 {
		t.Fatalf("score tie was not resolved in source order: %#v", result.Functions)
	}
	if !strings.Contains(string(result.YARA), "Function: first") || strings.Contains(string(result.YARA), "Function: second") {
		t.Fatalf("unexpected selected functions:\n%s", result.YARA)
	}

	args.MaxRules = 2
	args.Functions = []string{"second"}
	filtered, err := Generate(context.Background(), object, spec.Metadata{Name: "Filter"}, args, fixedOptions(testFactory(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Functions) != 1 || filtered.Functions[0].Name != "second" || filtered.RuleCount != 1 {
		t.Fatalf("unexpected filtered result: %#v", filtered)
	}
	if strings.Contains(string(filtered.YARA), "Function: first") || !strings.Contains(string(filtered.YARA), "Function: second") {
		t.Fatalf("function filter failed:\n%s", filtered.YARA)
	}
}

func TestGenerateNoRulesAndMissingTargetWarnings(t *testing.T) {
	code := []byte{0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0xc3}
	object, _ := testObject(t, coff.MachineAMD64, code, map[string]uint32{"straight": 0})
	args := generateArgs()
	args.Functions = []string{"straight", "absent"}
	result, err := Generate(context.Background(), object, spec.Metadata{}, args, fixedOptions(testFactory(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if result.RuleName != "TCG_12345678" || result.RuleCount != 0 || len(result.YARA) != 0 {
		t.Fatalf("unexpected no-rules result: %#v", result)
	}
	if countWarning(result.Warnings, WarningNoRules) != 1 || countWarning(result.Warnings, WarningTargetMissing) != 1 {
		t.Fatalf("warnings = %#v", result.Warnings)
	}
	last := result.Warnings[len(result.Warnings)-1]
	if last.Code != WarningNoRules || last.Message != "TCG_12345678: No invariant islands matching Yara rule generator criteria exist" {
		t.Fatalf("no-rules warning = %#v", last)
	}
}

func TestGenerateZeroMaximumDoesNoWork(t *testing.T) {
	called := false
	options := fixedOptions(func(context.Context, x86.Mode) (x86.Disassembler, error) {
		called = true
		return nil, errors.New("should not be called")
	})
	result, err := Generate(context.Background(), &coff.Object{Machine: coff.MachineAMD64}, spec.Metadata{}, Args{
		MaxRules: 0, Agreement: 5, MinLength: 10, MaxLength: 16,
	}, options)
	if err != nil {
		t.Fatal(err)
	}
	if called || result.RuleName != "" || len(result.YARA) != 0 {
		t.Fatalf("disabled generator did work: called=%v result=%#v", called, result)
	}
}

func TestGenerateRejectsMalformedInputs(t *testing.T) {
	validArgs := generateArgs()
	if _, err := Generate(nil, &coff.Object{}, spec.Metadata{}, validArgs, GenerateOptions{}); !errors.Is(err, ErrNilContext) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := Generate(context.Background(), nil, spec.Metadata{}, validArgs, GenerateOptions{}); !errors.Is(err, ErrNilObject) {
		t.Fatalf("nil object error = %v", err)
	}
	if _, err := Generate(context.Background(), &coff.Object{Machine: coff.MachineARM64}, spec.Metadata{}, validArgs, GenerateOptions{}); !errors.Is(err, ErrUnsupportedMachine) {
		t.Fatalf("ARM64 error = %v", err)
	}

	outside, section := testObject(t, coff.MachineAMD64, []byte{0xc3}, nil)
	if err := outside.AddSymbol(coff.NewFunctionSymbol(section, "outside", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(context.Background(), outside, spec.Metadata{}, validArgs, fixedOptions(testFactory(nil))); !errors.Is(err, ErrMalformedObject) {
		t.Fatalf("outside function error = %v", err)
	}

	badDecode, _ := testObject(t, coff.MachineAMD64, []byte{0xc3}, map[string]uint32{"bad": 0})
	options := fixedOptions(func(context.Context, x86.Mode) (x86.Disassembler, error) {
		return &testDisassembler{decode: func(context.Context, []byte, uint64) ([]x86.Instruction, error) {
			return []x86.Instruction{{Address: 1, Bytes: []byte{0xc3}, Mnemonic: "ret"}}, nil
		}}, nil
	})
	if _, err := Generate(context.Background(), badDecode, spec.Metadata{}, validArgs, options); !errors.Is(err, ErrMalformedObject) {
		t.Fatalf("inconsistent decoder error = %v", err)
	}

	crossing, crossingSection := testObject(t, coff.MachineAMD64,
		[]byte{0xeb, 0x0e, 0x48, 0x8b, 0x05, 1, 2, 3, 4, 0xe8, 1, 0, 0, 0, 0x31, 0xc0, 0xc3},
		map[string]uint32{"crossing": 0},
	)
	crossingSection.Relocations = []*coff.Relocation{{
		Section: crossingSection, VirtualAddress: 3, Type: coff.RelAMD64Addr64,
	}}
	if _, err := Generate(context.Background(), crossing, spec.Metadata{}, validArgs, fixedOptions(testFactory(nil))); !errors.Is(err, ErrMalformedObject) {
		t.Fatalf("crossing relocation error = %v", err)
	}
}

func TestGenerateConservativelyOmitsUnknownControlFlow(t *testing.T) {
	object, _ := testObject(t, coff.MachineAMD64, []byte{0x66, 0xe9, 0, 0, 0, 0, 0xc3}, map[string]uint32{"prefixed": 0})
	options := fixedOptions(func(context.Context, x86.Mode) (x86.Disassembler, error) {
		return &testDisassembler{decode: func(_ context.Context, _ []byte, address uint64) ([]x86.Instruction, error) {
			return []x86.Instruction{
				{Address: address, Bytes: []byte{0x66, 0xe9, 0, 0, 0, 0}, Mnemonic: "jmp", Operands: "6"},
				{Address: address + 6, Bytes: []byte{0xc3}, Mnemonic: "ret"},
			}, nil
		}}, nil
	})
	result, err := Generate(context.Background(), object, spec.Metadata{}, generateArgs(), options)
	if err != nil {
		t.Fatal(err)
	}
	if result.RuleCount != 0 || countWarning(result.Warnings, WarningControlFlow) != 1 {
		t.Fatalf("unsafe control flow was not conservatively omitted: %#v", result)
	}
}

func TestGenerateContextLifecycleAndCloseErrors(t *testing.T) {
	object, _ := testObject(t, coff.MachineAMD64, []byte{0xc3}, map[string]uint32{"f": 0})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	options := fixedOptions(func(context.Context, x86.Mode) (x86.Disassembler, error) {
		called = true
		return &testDisassembler{}, nil
	})
	if _, err := Generate(ctx, object, spec.Metadata{}, generateArgs(), options); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v", err)
	}
	if called {
		t.Fatal("factory called for pre-canceled context")
	}

	closeSentinel := errors.New("close failed")
	options = fixedOptions(func(context.Context, x86.Mode) (x86.Disassembler, error) {
		return &testDisassembler{closeErr: closeSentinel}, nil
	})
	if _, err := Generate(context.Background(), object, spec.Metadata{}, generateArgs(), options); !errors.Is(err, closeSentinel) {
		t.Fatalf("close error = %v", err)
	}
}

func TestGenerateConcurrentDeterminism(t *testing.T) {
	code := []byte{0xeb, 0x0e, 0x48, 0x8b, 0x05, 1, 2, 3, 4, 0xe8, 1, 0, 0, 0, 0x31, 0xc0, 0xc3}
	object, _ := testObject(t, coff.MachineAMD64, code, map[string]uint32{"concurrent": 0})
	options := fixedOptions(testFactory(nil))
	const workers = 24
	outputs := make([][]byte, workers)
	errorsFound := make([]error, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			result, err := Generate(context.Background(), object, spec.Metadata{Name: "Concurrent"}, generateArgs(), options)
			errorsFound[index] = err
			outputs[index] = result.YARA
		}(index)
	}
	group.Wait()
	for index := range outputs {
		if errorsFound[index] != nil {
			t.Fatalf("worker %d: %v", index, errorsFound[index])
		}
		if !bytes.Equal(outputs[0], outputs[index]) {
			t.Fatalf("worker %d output differs", index)
		}
	}
}

func TestUUIDRandomInjectionCreatesVersionFourVariant(t *testing.T) {
	value, err := makeUUID(GenerateOptions{Random: bytes.NewReader(make([]byte, 16))})
	if err != nil {
		t.Fatal(err)
	}
	if value != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("UUID = %q", value)
	}
	if _, err := makeUUID(GenerateOptions{Random: strings.NewReader("short")}); err == nil {
		t.Fatal("short random source succeeded")
	}
}

func TestRelocationWidths(t *testing.T) {
	tests := []struct {
		machine coff.Machine
		typeID  uint16
		width   int
		known   bool
	}{
		{coff.MachineAMD64, coff.RelAMD64Addr64, 8, true},
		{coff.MachineAMD64, coff.RelAMD64Rel32, 4, true},
		{coff.MachineI386, coff.RelI386Dir32, 4, true},
		{coff.MachineI386, 0xffff, 0, false},
	}
	for _, test := range tests {
		width, known := relocationWidth(test.machine, test.typeID)
		if width != test.width || known != test.known {
			t.Fatalf("relocationWidth(%s, %#x) = %d,%v, want %d,%v", test.machine, test.typeID, width, known, test.width, test.known)
		}
	}
}

func testObject(t *testing.T, machine coff.Machine, code []byte, functions map[string]uint32) (*coff.Object, *coff.Section) {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	section := coff.NewSection(".text", code)
	if err := object.AddSection(section); err != nil {
		t.Fatal(err)
	}
	type namedOffset struct {
		name   string
		offset uint32
	}
	ordered := make([]namedOffset, 0, len(functions))
	for name, offset := range functions {
		ordered = append(ordered, namedOffset{name: name, offset: offset})
	}
	// The fixture API accepts a map for readability but inserts deterministically.
	for index := 0; index < len(ordered); index++ {
		for next := index + 1; next < len(ordered); next++ {
			if ordered[next].offset < ordered[index].offset || ordered[next].offset == ordered[index].offset && ordered[next].name < ordered[index].name {
				ordered[index], ordered[next] = ordered[next], ordered[index]
			}
		}
	}
	for _, function := range ordered {
		if err := object.AddSymbol(coff.NewFunctionSymbol(section, function.name, function.offset)); err != nil {
			t.Fatal(err)
		}
	}
	return object, section
}

func decodeTestInstructions(ctx context.Context, code []byte, address uint64) ([]x86.Instruction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]x86.Instruction, 0)
	for offset := 0; offset < len(code); {
		remaining := code[offset:]
		instruction := x86.Instruction{Address: address + uint64(offset)}
		size := 0
		switch {
		case len(remaining) >= 2 && remaining[0] == 0xeb:
			size, instruction.Mnemonic = 2, "jmp"
			instruction.Operands = fmt.Sprintf("%#x", instruction.Address+2+uint64(int64(int8(remaining[1]))))
		case len(remaining) >= 7 && reflect.DeepEqual(remaining[:3], []byte{0x48, 0x8b, 0x05}):
			size, instruction.Mnemonic, instruction.Operands = 7, "mov", "rax, qword ptr [rip + 0x44332211]"
		case len(remaining) >= 5 && remaining[0] == 0xb8:
			size, instruction.Mnemonic, instruction.Operands = 5, "mov", "eax, 0x44332211"
		case len(remaining) >= 5 && remaining[0] == 0xe8:
			size, instruction.Mnemonic, instruction.Operands = 5, "call", "0x0"
		case len(remaining) >= 2 && remaining[0] == 0x31:
			size, instruction.Mnemonic, instruction.Operands = 2, "xor", "eax, eax"
		case len(remaining) >= 1 && remaining[0] == 0x55:
			size, instruction.Mnemonic, instruction.Operands = 1, "push", "rbp"
		case len(remaining) >= 3 && reflect.DeepEqual(remaining[:3], []byte{0x48, 0x89, 0xe5}):
			size, instruction.Mnemonic, instruction.Operands = 3, "mov", "rbp, rsp"
		case len(remaining) >= 1 && remaining[0] == 0xc3:
			size, instruction.Mnemonic = 1, "ret"
		case len(remaining) >= 1 && remaining[0] == 0x90:
			size, instruction.Mnemonic = 1, "nop"
		default:
			return nil, fmt.Errorf("test decoder: unknown bytes at %d: %x", offset, remaining)
		}
		instruction.Bytes = append([]byte(nil), remaining[:size]...)
		result = append(result, instruction)
		offset += size
	}
	return result, nil
}

func countWarning(warnings []Warning, code string) int {
	count := 0
	for _, warning := range warnings {
		if warning.Code == code {
			count++
		}
	}
	return count
}

func FuzzClassifyFlowNeverPanics(f *testing.F) {
	f.Add([]byte{0xeb, 0})
	f.Add([]byte{0x0f, 0x85, 1, 0, 0, 0})
	f.Add([]byte{0xc3})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, code []byte) {
		_ = classifyFlow(x86.Instruction{Address: 0x1000, Bytes: code, Mnemonic: "jmp"})
	})
}

func FuzzNewRuleMasks(f *testing.F) {
	f.Add([]byte{0xe8, 1, 2, 3, 4}, uint8(2))
	f.Add([]byte{0x90}, uint8(0))
	f.Fuzz(func(t *testing.T, code []byte, wildcardIndex uint8) {
		if len(code) == 0 || len(code) > 15 {
			t.Skip()
		}
		mask := make([]bool, len(code))
		mask[int(wildcardIndex)%len(mask)] = true
		rule, err := NewRule([]RuleInstruction{{Instruction: x86.Instruction{Bytes: code}, Wildcards: mask}})
		if err != nil {
			t.Fatal(err)
		}
		if len(rule.Content()) != len(code) || len(rule.Wildcards()) != len(code) {
			t.Fatalf("length mismatch for %x", code)
		}
	})
}
