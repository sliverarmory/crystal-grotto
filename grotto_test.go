// SPDX-License-Identifier: GPL-3.0-only

package grotto_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	grotto "github.com/sliverarmory/crystal-grotto"
)

func TestPublicParseAndRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bytes.spec")
	if err := os.WriteFile(path, []byte("x64:\n  push $DATA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	program, err := grotto.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := grotto.None("x64")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	got, err := program.Run(capability, grotto.RunOptions{Environment: grotto.Environment{"$DATA": want}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Run() = %x, want %x", got, want)
	}
}

func TestVersionConstants(t *testing.T) {
	t.Parallel()
	if grotto.Version == "" || grotto.UpstreamVersion != "06.29.26" || grotto.CompatibilityBaseline != "2026-07-16" {
		t.Fatalf("unexpected versions: %q, %q, %q", grotto.Version, grotto.UpstreamVersion, grotto.CompatibilityBaseline)
	}
}

func TestPublicExecutionUsesDefaultEngine(t *testing.T) {
	t.Parallel()
	code := []byte{0xb8, 0x2a, 0, 0, 0, 0xc3}
	object := minimalPublicX64COFF(code)
	capability, err := grotto.ParseObject(object)
	if err != nil {
		t.Fatal(err)
	}
	program, err := grotto.Parse("default-engine.spec", "x64.o:\n  push $OBJECT\n  make pic64\n  export\n")
	if err != nil {
		t.Fatal(err)
	}
	output, err := program.Run(capability, grotto.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, code) {
		t.Fatalf("Run output = %x, want %x", output, code)
	}
	generated, err := program.RunAndGenerate(capability, grotto.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated.Program, code) || len(generated.Rules) != 0 {
		t.Fatalf("RunAndGenerate = program %x, rules %x", generated.Program, generated.Rules)
	}

	config, err := grotto.Parse("default-config.spec", "x64.o:\n  push $OBJECT\n  make coff\n  export\n  pop $CONFIGURED\n")
	if err != nil {
		t.Fatal(err)
	}
	environment, err := config.RunConfig(capability, grotto.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	configured, ok := environment["$CONFIGURED"].([]byte)
	if !ok || len(configured) == 0 {
		t.Fatalf("RunConfig did not export COFF bytes: %#v", environment["$CONFIGURED"])
	}
	if _, err := grotto.ParseObject(configured); err != nil {
		t.Fatalf("RunConfig output is not COFF: %v", err)
	}
}

type passthroughHandler struct{ calls int }

func (h *passthroughHandler) Handle(context *grotto.ExecutionContext, command *grotto.Command, _ []string) (bool, error) {
	if command.Name() != "make" {
		return false, nil
	}
	value, err := context.Pop()
	if err != nil {
		return true, err
	}
	h.calls++
	context.Push(value)
	return true, nil
}

func TestPublicExecutionPreservesExplicitHandler(t *testing.T) {
	t.Parallel()
	program, err := grotto.Parse("custom-handler.spec", "x64:\n  push $DATA\n  make pic64\n")
	if err != nil {
		t.Fatal(err)
	}
	capability, err := grotto.None("x64")
	if err != nil {
		t.Fatal(err)
	}
	handler := &passthroughHandler{}
	want := []byte("handled")
	got, err := program.Run(capability, grotto.RunOptions{Environment: grotto.Environment{"$DATA": want}, Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || handler.calls != 1 {
		t.Fatalf("custom handler output=%q calls=%d", got, handler.calls)
	}
}

func minimalPublicX64COFF(code []byte) []byte {
	const headerSize = 20 + 40
	result := make([]byte, headerSize+len(code))
	binary.LittleEndian.PutUint16(result[0:2], 0x8664)
	binary.LittleEndian.PutUint16(result[2:4], 1)
	copy(result[20:28], []byte(".text"))
	binary.LittleEndian.PutUint32(result[36:40], uint32(len(code)))
	binary.LittleEndian.PutUint32(result[40:44], headerSize)
	binary.LittleEndian.PutUint32(result[56:60], 0x60000020)
	copy(result[headerSize:], code)
	return result
}
