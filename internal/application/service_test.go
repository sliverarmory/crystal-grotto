// SPDX-License-Identifier: GPL-3.0-only

package application

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/server"
)

func TestServiceBuildAndConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	config := filepath.Join(dir, "config.spec")
	program := filepath.Join(dir, "program.spec")
	writeTestFile(t, config, "x64:\n  pack $PREFIX \"h\" cafe\n")
	writeTestFile(t, program, "x64:\n  pack $OUT \"vv\" $PREFIX $DATA\n  push $OUT\n")

	result, err := (Service{}).Build(context.Background(), server.BuildRequest{
		Spec:        program,
		Arch:        "x64",
		Config:      []string{config},
		Environment: server.Environment{"$DATA": []byte{0xbe, 0xef}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xca, 0xfe, 0xbe, 0xef}; !bytes.Equal(result.Output, want) {
		t.Fatalf("output = %x, want %x", result.Output, want)
	}
}

func TestServiceCollectsProgramMessages(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	program := filepath.Join(dir, "message.spec")
	writeTestFile(t, program, "x64:\n  echo \"hello\"\n  push $NULL\n")
	result, err := (Service{}).Build(context.Background(), server.BuildRequest{Spec: program, Arch: "x64"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Message != "[*] hello in message.spec (x64)" {
		t.Fatalf("message = %q", result.Message)
	}
}

func TestServiceConfigHooksPersistIntoProgram(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	config := filepath.Join(dir, "hooks.spec")
	program := filepath.Join(dir, "program.spec")
	writeTestFile(t, config, "x64:\n  before \"push\": echo \"before\" %_\n  after \"push\": echo \"after\" %_\n")
	writeTestFile(t, program, "x64:\n  push $NULL\n")

	result, err := (Service{}).Build(context.Background(), server.BuildRequest{
		Spec:   program,
		Arch:   "x64",
		Config: []string{config},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "[*] before push $NULL in program.spec (x64)\n[*] after push $NULL in program.spec (x64)"
	if result.Message != want {
		t.Fatalf("message = %q, want %q", result.Message, want)
	}
}

func TestServiceReportsSpecContext(t *testing.T) {
	t.Parallel()
	_, err := (Service{}).Build(context.Background(), server.BuildRequest{Spec: filepath.Join(t.TempDir(), "missing.spec"), Arch: "x64"})
	if err == nil {
		t.Fatal("Build() succeeded")
	}
	contextual, ok := err.(interface{ SidecarContext() string })
	if !ok || contextual.SidecarContext() != "params.spec" {
		t.Fatalf("error context = %T %v", err, err)
	}
}

func TestServiceReportsInvalidArchitectureAtInit(t *testing.T) {
	t.Parallel()
	_, err := (Service{}).Build(context.Background(), server.BuildRequest{Spec: "unused.spec", Arch: "arm64"})
	if err == nil {
		t.Fatal("Build() succeeded")
	}
	contextual, ok := err.(interface{ SidecarContext() string })
	if !ok || contextual.SidecarContext() != "Init" {
		t.Fatalf("error context = %T %v", err, err)
	}
}

func TestServiceUsesDefaultEngineForLinkAndGenerate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	program := filepath.Join(dir, "link.spec")
	objectPath := filepath.Join(dir, "module.x64.o")
	writeTestFile(t, program, "x64.o:\n  push $OBJECT\n  make pic64\n  export\n")
	code := []byte{0xb8, 0x2a, 0, 0, 0, 0xc3}
	if err := os.WriteFile(objectPath, minimalServiceX64COFF(code), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := (Service{}).Link(context.Background(), server.LinkRequest{
		Spec: program,
		File: objectPath,
		Yara: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Output, code) || len(result.Yara) != 0 {
		t.Fatalf("default engine result = output %x, yara %x", result.Output, result.Yara)
	}
	if service := NewService(); service.NewHandler == nil || service.NewHandler() == nil {
		t.Fatal("NewService did not install an engine handler factory")
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func minimalServiceX64COFF(code []byte) []byte {
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
