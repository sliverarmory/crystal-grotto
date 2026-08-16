// SPDX-License-Identifier: GPL-3.0-only

package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootUsesCobraCommandContract(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	command := NewRootCommand(Streams{In: strings.NewReader(""), Out: &stdout, Err: &stderr})
	want := []string{"build", "coffparse", "disassemble", "link", "server"}
	for _, name := range want {
		found, _, err := command.Find([]string{name})
		if err != nil || found == nil || found.Name() != name {
			t.Fatalf("Find(%q) = %v, %v", name, found, err)
		}
	}
	for _, hidden := range []string{"run", "buildPic"} {
		found, _, err := command.Find([]string{hidden})
		if err != nil || found == nil || !found.Hidden {
			t.Fatalf("legacy command %q not registered and hidden", hidden)
		}
	}
}

func TestServerDieEndpointRequiresExplicitFlag(t *testing.T) {
	t.Parallel()
	command := newServerCommand()
	flag := command.Flags().Lookup("enable-die")
	if flag == nil {
		t.Fatal("server command is missing --enable-die")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--enable-die default = %q, want false", flag.DefValue)
	}
}

func TestBuildEndToEnd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	specPath := filepath.Join(dir, "build.spec")
	outputPath := filepath.Join(dir, "out.bin")
	content := "x64:\n  pack $PREFIX \"h\" cafe\n  pack $RESULT \"vvz\" $PREFIX $PAYLOAD %name\n  push $RESULT\n"
	if err := os.WriteFile(specPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Execute(context.Background(), []string{"build", specPath, "x64", outputPath, "PAYLOAD=beef", "%name=grotto"}, Streams{In: strings.NewReader(""), Out: &stdout, Err: &stderr})
	if err != nil {
		t.Fatalf("Execute() error = %v, stderr=%q", err, stderr.String())
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xca, 0xfe, 0xbe, 0xef, 'g', 'r', 'o', 't', 't', 'o', 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("output = %x, want %x", got, want)
	}
}

func TestProcessArgumentsPreservesOrder(t *testing.T) {
	t.Parallel()
	environment := make(map[string]any)
	capability, err := noneForTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := processArguments([]string{"A=00ff", "%name=first", "%name=second"}, capability, runOptionsForTest(environment)); err != nil {
		t.Fatal(err)
	}
	if got := environment["%name"]; got != "second" {
		t.Fatalf("%%name = %#v", got)
	}
	if got, ok := environment["$A"].([]byte); !ok || !bytes.Equal(got, []byte{0, 0xff}) {
		t.Fatalf("$A = %#v", environment["$A"])
	}
}

func TestCOFFParseAndDisassembleCommands(t *testing.T) {
	dir := t.TempDir()
	objectPath := filepath.Join(dir, "return42.x64.o")
	if err := os.WriteFile(objectPath, minimalX64COFF([]byte{0xb8, 0x2a, 0, 0, 0, 0xc3}), 0o600); err != nil {
		t.Fatal(err)
	}

	var parseOutput, parseErrors bytes.Buffer
	if err := Execute(context.Background(), []string{"coffparse", objectPath}, Streams{Out: &parseOutput, Err: &parseErrors}); err != nil {
		t.Fatalf("coffparse: %v", err)
	}
	for _, want := range []string{"COFF Object (x64)", ".text", "size=6"} {
		if !strings.Contains(parseOutput.String(), want) {
			t.Errorf("coffparse output %q does not contain %q", parseOutput.String(), want)
		}
	}
	var extraOutput bytes.Buffer
	if err := Execute(context.Background(), []string{"coffparse", objectPath, "ignored"}, Streams{Out: &extraOutput}); err != nil {
		t.Fatalf("coffparse with ignored extra argument: %v", err)
	}
	if extraOutput.String() != parseOutput.String() {
		t.Fatalf("coffparse extra argument changed output\nplain: %q\nextra: %q", parseOutput.String(), extraOutput.String())
	}

	var disassembly, disassemblyErrors bytes.Buffer
	if err := Execute(context.Background(), []string{"disassemble", objectPath}, Streams{Out: &disassembly, Err: &disassemblyErrors}); err != nil {
		t.Fatalf("disassemble: %v", err)
	}
	for _, want := range []string{".text (x64, 6 bytes)", "mov eax, 0x2a", "ret"} {
		if !strings.Contains(disassembly.String(), want) {
			t.Errorf("disassembly %q does not contain %q", disassembly.String(), want)
		}
	}
}

func TestBuildAndLinkCommandsUseDefaultEngine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	code := []byte{0xb8, 0x2a, 0, 0, 0, 0xc3}
	object := minimalX64COFF(code)

	buildSpec := filepath.Join(dir, "build-engine.spec")
	buildOutput := filepath.Join(dir, "build.bin")
	rulesOutput := filepath.Join(dir, "build.yar")
	if err := os.WriteFile(buildSpec, []byte("x64:\n  push $OBJECT\n  make pic64\n  export\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buildStdout, buildStderr bytes.Buffer
	if err := Execute(context.Background(), []string{
		"build", buildSpec, "x64", buildOutput,
		"OBJECT=" + hex.EncodeToString(object), "-g", rulesOutput,
	}, Streams{Out: &buildStdout, Err: &buildStderr}); err != nil {
		t.Fatalf("build: %v, stderr=%q", err, buildStderr.String())
	}
	assertFileBytes(t, buildOutput, code)
	assertFileBytes(t, rulesOutput, nil)

	linkSpec := filepath.Join(dir, "link-engine.spec")
	objectPath := filepath.Join(dir, "module.x64.o")
	linkOutput := filepath.Join(dir, "link.bin")
	if err := os.WriteFile(linkSpec, []byte("x64.o:\n  push $OBJECT\n  make pic64\n  export\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath, object, 0o600); err != nil {
		t.Fatal(err)
	}
	var linkStdout, linkStderr bytes.Buffer
	if err := Execute(context.Background(), []string{"link", linkSpec, objectPath, linkOutput}, Streams{Out: &linkStdout, Err: &linkStderr}); err != nil {
		t.Fatalf("link: %v, stderr=%q", err, linkStderr.String())
	}
	assertFileBytes(t, linkOutput, code)
}

func assertFileBytes(t testing.TB, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %x, want %x", path, got, want)
	}
}

func minimalX64COFF(code []byte) []byte {
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
