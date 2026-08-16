// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/coffwrite"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestDisassembleAppliesDeterministicBTFOptions(t *testing.T) {
	tests := []struct {
		name      string
		machine   coff.Machine
		code      []byte
		functions []inspectFunction
		option    string
		wantSize  string
		first     string
		second    string
		absent    string
	}{
		{
			name:    "gofirst reorders functions",
			machine: coff.MachineAMD64,
			code: []byte{
				0xb8, 0x11, 0, 0, 0, 0xc3,
				0xb8, 0x22, 0, 0, 0, 0xc3,
			},
			functions: []inspectFunction{{"helper", 0}, {"go", 6}},
			option:    "+gofirst",
			wantSize:  ".text (x64, 12 bytes)",
			first:     "mov eax, 0x22",
			second:    "mov eax, 0x11",
		},
		{
			name:    "optimize removes unreachable function",
			machine: coff.MachineI386,
			code: []byte{
				0xb8, 0x22, 0, 0, 0, 0xc3,
				0xb8, 0x11, 0, 0, 0, 0xc3,
			},
			functions: []inspectFunction{{"_go", 0}, {"_dead", 6}},
			option:    "+optimize",
			wantSize:  ".text (x86, 6 bytes)",
			first:     "mov eax, 0x22",
			absent:    "mov eax, 0x11",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := inspectCOFF(t, test.machine, test.code, test.functions...)
			output, err := runDisassemble(t, input, "-o", test.option)
			if err != nil {
				t.Fatalf("disassemble: %v", err)
			}
			if !strings.Contains(output, test.wantSize) {
				t.Fatalf("output %q does not contain %q", output, test.wantSize)
			}
			first := strings.Index(output, test.first)
			if first < 0 {
				t.Fatalf("output %q does not contain %q", output, test.first)
			}
			if test.second != "" {
				second := strings.Index(output, test.second)
				if second < 0 || first >= second {
					t.Fatalf("transformed order is wrong in %q", output)
				}
			}
			if test.absent != "" && strings.Contains(output, test.absent) {
				t.Fatalf("output %q unexpectedly contains %q", output, test.absent)
			}
		})
	}
}

func TestDisassembleEmptyOptionsKeepsNoOptionOutput(t *testing.T) {
	input := inspectCOFF(t, coff.MachineAMD64, []byte{0xb8, 0x2a, 0, 0, 0, 0xc3}, inspectFunction{"go", 0})
	plain, err := runDisassemble(t, input)
	if err != nil {
		t.Fatalf("plain disassemble: %v", err)
	}
	emptyOptions, err := runDisassemble(t, input, "-o", "")
	if err != nil {
		t.Fatalf("disassemble with empty options: %v", err)
	}
	if emptyOptions != plain {
		t.Fatalf("empty -o changed no-option output:\nplain: %q\nempty: %q", plain, emptyOptions)
	}
}

func TestDisassembleWithoutOptionsNormalizesTextSubsections(t *testing.T) {
	object, err := coff.NewObject(coff.MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	first := coff.NewSection(".text$A", []byte{0x90, 0xc3})
	second := coff.NewSection(".text$B", []byte{0xcc, 0xc3})
	if err := object.AddSection(first); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSection(second); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(coff.NewFunctionSymbol(first, "go", 0)); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(coff.NewFunctionSymbol(second, "helper", 0)); err != nil {
		t.Fatal(err)
	}
	input, err := coffwrite.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	output, err := runDisassemble(t, input)
	if err != nil {
		t.Fatalf("disassemble: %v", err)
	}
	if strings.Count(output, ".text (x64, 4 bytes)") != 1 {
		t.Fatalf("normalized output = %q", output)
	}
	if strings.Contains(output, ".text$A") || strings.Contains(output, ".text$B") {
		t.Fatalf("raw subsection names survived normalization: %q", output)
	}
}

func TestDisassembleFormsUsesProvenISEDForms(t *testing.T) {
	for _, test := range []struct {
		name      string
		machine   coff.Machine
		code      []byte
		function  string
		wantForms []string
	}{
		{
			name:     "x64",
			machine:  coff.MachineAMD64,
			code:     []byte{0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0xe5, 0x48, 0x31, 0xc0, 0xc3},
			function: "go",
			wantForms: []string{
				"PUSH r64", "SUB r/m64, imm8", "MOV r/m64, r64", "XOR r/m64, r64", "RET",
			},
		},
		{
			name:     "x86",
			machine:  coff.MachineI386,
			code:     []byte{0x53, 0x89, 0xe5, 0x31, 0xc0, 0xc3},
			function: "_go",
			wantForms: []string{
				"PUSH r32", "MOV r/m32, r32", "XOR r/m32, r32", "RET",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := inspectCOFF(t, test.machine, test.code, inspectFunction{test.function, 0})
			plain, err := runDisassemble(t, input)
			if err != nil {
				t.Fatalf("plain disassemble: %v", err)
			}
			if strings.Contains(plain, "; ") {
				t.Fatalf("plain disassembly unexpectedly contains a form: %q", plain)
			}
			withForms, err := runDisassemble(t, input, "-f")
			if err != nil {
				t.Fatalf("forms disassemble: %v", err)
			}
			for _, form := range test.wantForms {
				if !strings.Contains(withForms, "; "+form) {
					t.Errorf("forms disassembly %q does not contain %q", withForms, form)
				}
			}
		})
	}
}

func TestDisassembleFormsOmitUnsupportedAndOutOfFunctionInstructions(t *testing.T) {
	object, err := coff.NewObject(coff.MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	// PAUSE is outside the conservative ISED raw-form subset. The final RET is
	// behind a global-data boundary and therefore outside a function.
	text := coff.NewSection(".text", []byte{0x90, 0xf3, 0x90, 0xc3})
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(coff.NewFunctionSymbol(text, "go", 0)); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSymbol(coff.NewDataSymbol(text, "literal", 3)); err != nil {
		t.Fatal(err)
	}
	input, err := coffwrite.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	output, err := runDisassemble(t, input, "-f")
	if err != nil {
		t.Fatalf("forms disassemble: %v", err)
	}
	if line := disassemblyLineAt(output, "0000000000000000 "); !strings.Contains(line, "; NOP") {
		t.Fatalf("proven instruction line = %q, want NOP form", line)
	}
	if line := disassemblyLineAt(output, "0000000000000001 "); !strings.Contains(line, "pause") || strings.Contains(line, "; ") {
		t.Fatalf("unsupported instruction line = %q, want form omission", line)
	}
	if line := disassemblyLineAt(output, "0000000000000003 "); !strings.Contains(line, "ret") || strings.Contains(line, "; ") {
		t.Fatalf("out-of-function instruction line = %q, want form omission", line)
	}
}

func TestDisassembleFormsHonorsCanceledCobraContext(t *testing.T) {
	input := inspectCOFF(t, coff.MachineAMD64, []byte{0x90, 0xc3}, inspectFunction{"go", 0})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runDisassembleContext(t, ctx, input, "-f")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("disassemble -f error = %v, want context.Canceled", err)
	}
}

func TestProvenTextFormsLeavesCallerOwnedDecoderOpen(t *testing.T) {
	input := inspectCOFF(t, coff.MachineAMD64, []byte{0x90, 0xc3}, inspectFunction{"go", 0})
	object, err := coff.Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	decoder, err := x86.NewCapstone(ctx, x86.Mode64)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = decoder.Close(context.Background()) }()
	forms, err := provenTextForms(ctx, object, decoder)
	if err != nil {
		t.Fatal(err)
	}
	if forms[0] != "NOP" || forms[1] != "RET" {
		t.Fatalf("forms = %#v", forms)
	}
	if decoder.IsClosed() {
		t.Fatal("provenTextForms closed its caller-owned decoder")
	}
	if _, err := decoder.Disassemble(ctx, object.GetSection(".text").Data, 0); err != nil {
		t.Fatalf("reuse caller-owned decoder: %v", err)
	}
}

func TestParseDisassemblyOptions(t *testing.T) {
	got, err := parseDisassemblyOptions(" +gofirst, +optimize,+gofirst  +unwind ")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"+gofirst", "+optimize", "+unwind"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("options = %v, want %v", got, want)
	}
	if got, err := parseDisassemblyOptions(" ,  , "); err != nil || len(got) != 0 {
		t.Fatalf("blank options = %v, %v", got, err)
	}
	for _, input := range []string{"+unknown", "+gofirst\nexport", "gofirst"} {
		if _, err := parseDisassemblyOptions(input); err == nil {
			t.Fatalf("unsafe/unsupported options %q accepted", input)
		}
	}
	if _, err := parseDisassemblyOptions("+unwind,+shatter"); err == nil || !strings.Contains(err.Error(), "+shatter and +unwind") {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestDisassembleRejectsInvalidAndIncompatibleOptions(t *testing.T) {
	input := inspectCOFF(t, coff.MachineAMD64, []byte{0xc3}, inspectFunction{"go", 0})
	for _, test := range []struct {
		option string
		want   string
	}{
		{option: "+bogus", want: "invalid BTF disassembly option"},
		{option: "+shatter,+unwind", want: "Options +shatter and +unwind are not compatible"},
	} {
		_, err := runDisassemble(t, input, "-o", test.option)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("disassemble -o %q error = %v, want %q", test.option, err, test.want)
		}
	}
}

type inspectFunction struct {
	name  string
	value uint32
}

func inspectCOFF(t testing.TB, machine coff.Machine, code []byte, functions ...inspectFunction) []byte {
	t.Helper()
	object, err := coff.NewObject(machine)
	if err != nil {
		t.Fatal(err)
	}
	text := coff.NewSection(".text", code)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	for _, function := range functions {
		if err := object.AddSymbol(coff.NewFunctionSymbol(text, function.name, function.value)); err != nil {
			t.Fatal(err)
		}
	}
	output, err := coffwrite.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func runDisassemble(t testing.TB, input []byte, arguments ...string) (string, error) {
	return runDisassembleContext(t, context.Background(), input, arguments...)
}

func runDisassembleContext(t testing.TB, ctx context.Context, input []byte, arguments ...string) (string, error) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "input.o")
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"disassemble"}, arguments...)
	args = append(args, path)
	var stdout, stderr bytes.Buffer
	err := Execute(ctx, args, Streams{Out: &stdout, Err: &stderr})
	return stdout.String(), err
}

func disassemblyLineAt(output, prefix string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}
