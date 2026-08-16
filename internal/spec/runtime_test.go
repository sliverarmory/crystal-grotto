// SPDX-License-Identifier: GPL-3.0-only

package spec

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestRunPassthrough(t *testing.T) {
	t.Parallel()
	s := mustParse(t, "passthrough.spec", "x86:\n  push $PAYLOAD\nx64:\n  push $PAYLOAD\n")
	capability, err := None("x64")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 1, 2, 0xfe, 0xff}
	got, err := s.Run(capability, RunOptions{Environment: Environment{"$PAYLOAD": want}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Run() = %x, want %x", got, want)
	}
}

func TestRunPackAndTransforms(t *testing.T) {
	t.Parallel()
	s := mustParse(t, "stack.spec", `x64:
  pack $KEY "h" 0f0e
  pack $DATA "h" 0011223344
  push $DATA
  xor $KEY
  preplen
`)
	capability, _ := None("x64")
	got, err := s.Run(capability, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("050000000f1f2d3d4b")
	if !bytes.Equal(got, want) {
		t.Fatalf("Run() = %x, want %x", got, want)
	}
}

func TestRunConfigAndCall(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := map[string]string{
		"config.spec": "x64:\n  pack $PREFIX \"h\" cafe\n",
		"module.spec": "emit.x64:\n  pack $RESULT \"vz\" $PREFIX %1\n  push $RESULT\n",
		"main.spec":   "x64:\n  call \"module.spec\" \"emit\" \"grotto\"\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	capability, _ := None("x64")
	env := make(Environment)
	config := mustParse(t, filepath.Join(dir, "config.spec"), files["config.spec"])
	if _, err := config.RunConfig(capability, RunOptions{Environment: env}); err != nil {
		t.Fatal(err)
	}
	main := mustParse(t, filepath.Join(dir, "main.spec"), files["main.spec"])
	got, err := main.Run(capability, RunOptions{Environment: env})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("cafe67726f74746f00")
	if !bytes.Equal(got, want) {
		t.Fatalf("Run() = %x, want %x", got, want)
	}
}

func TestRunConfigHooksPersistAndRunCopiesEnvironment(t *testing.T) {
	t.Parallel()
	capability, _ := None("x64")
	env := Environment{"%original": "unchanged"}
	config := mustParse(t, "config.spec", `x64:
  setg "%configured" "yes"
  before "push": echo "before" %_
  after "push": echo "after" %_
`)
	configured, err := config.RunConfig(capability, RunOptions{Environment: env})
	if err != nil {
		t.Fatal(err)
	}
	if configured["%configured"] != "yes" || env["%configured"] != "yes" {
		t.Fatalf("RunConfig environment = %#v, want shared configured value", configured)
	}
	entriesBeforeRun := len(env)

	program := mustParse(t, "program.spec", `x64:
  setg "%runtime" "private"
  pack $TEMP "h" aa
  push $TEMP
`)
	var messages []string
	options := RunOptions{
		Environment: env,
		Logger: LoggerFunc(func(message Message) {
			messages = append(messages, message.Text)
		}),
	}
	for run := 0; run < 2; run++ {
		got, err := program.Run(capability, options)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, []byte{0xaa}) {
			t.Fatalf("Run() = %x, want aa", got)
		}
	}
	if _, ok := env["%runtime"]; ok {
		t.Fatal("ordinary Run mutated caller string environment")
	}
	if _, ok := env["$TEMP"]; ok {
		t.Fatal("ordinary Run mutated caller byte environment")
	}
	if len(env) != entriesBeforeRun || env["%original"] != "unchanged" || env["%configured"] != "yes" {
		t.Fatalf("caller environment changed across ordinary Run: %#v", env)
	}
	if want := []string{
		"before push $TEMP", "after push $TEMP",
		"before push $TEMP", "after push $TEMP",
	}; !reflect.DeepEqual(messages, want) {
		t.Fatalf("hook messages = %#v, want %#v", messages, want)
	}
}

func TestForeachAndEcho(t *testing.T) {
	t.Parallel()
	s := mustParse(t, "loop.spec", "x64:\nforeach \"a, b, c\": echo %_\npush $NULL\n")
	var messages []string
	capability, _ := None("x64")
	_, err := s.Run(capability, RunOptions{Logger: LoggerFunc(func(message Message) { messages = append(messages, message.Text) })})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(messages, want) {
		t.Fatalf("messages = %#v, want %#v", messages, want)
	}
}

func TestNextAndEcho(t *testing.T) {
	t.Parallel()
	s := mustParse(t, "next.spec", "x64:\nset \"%items\" \"a, b\"\nnext \"%items\": echo %_\nnext \"%items\": echo %_\npush $NULL\n")
	var messages []string
	capability, _ := None("x64")
	_, err := s.Run(capability, RunOptions{Logger: LoggerFunc(func(message Message) { messages = append(messages, message.Text) })})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a", "b"}; !reflect.DeepEqual(messages, want) {
		t.Fatalf("messages = %#v, want %#v", messages, want)
	}
}

func TestNestedForeachAndNextAreRejectedAtRuntime(t *testing.T) {
	t.Parallel()
	capability, _ := None("x64")
	for _, command := range []string{
		`foreach "a": foreach "b": echo %_`,
		`foreach "a": next "%items": echo %_`,
		`next "%items": foreach "b": echo %_`,
		`next "%items": next "%items": echo %_`,
	} {
		command := command
		t.Run(command, func(t *testing.T) {
			s := mustParse(t, "nested.spec", "x64:\nset \"%items\" \"a\"\n"+command+"\npush $NULL\n")
			_, err := s.Run(capability, RunOptions{})
			if err == nil || !strings.Contains(err.Error(), "Nested foreach/next is not allowed") {
				t.Fatalf("Run() error = %v, want nested-loop rejection", err)
			}
		})
	}
}

func TestSplitListMatchesJavaTrailingEmptySemantics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  []string
	}{
		{input: "", want: nil},
		{input: "a,", want: []string{"a"}},
		{input: "a,, ", want: []string{"a"}},
		{input: ",a,", want: []string{"", "a"}},
		{input: " , ", want: []string{""}},
		{input: ",", want: nil},
		{input: " a , b ", want: []string{"a", "b"}},
		{input: "a,\vb", want: []string{"a", "b"}},
	}
	for _, test := range tests {
		if got := splitList(test.input); !reflect.DeepEqual(got, test.want) {
			t.Errorf("splitList(%q) = %#v, want %#v", test.input, got, test.want)
		}
	}
}

func TestResolveValidatesAndCanonicalizesEveryPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := filepath.Join(dir, "first.bin")
	second := filepath.Join(dir, "second.bin")
	if err := os.WriteFile(first, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.bin")
	if err := os.Symlink(first, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	s := mustParse(t, filepath.Join(dir, "resolve.spec"), "x64:\nset \"%paths\" \"alias.bin, second.bin\"\nresolve \"%paths\"\necho %paths\npush $NULL\n")
	var messages []string
	capability, _ := None("x64")
	if _, err := s.Run(capability, RunOptions{Logger: LoggerFunc(func(message Message) {
		messages = append(messages, message.Text)
	})}); err != nil {
		t.Fatal(err)
	}
	canonicalFirst, err := filepath.EvalSymlinks(alias)
	if err != nil {
		t.Fatal(err)
	}
	canonicalSecond, err := filepath.EvalSymlinks(second)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{canonicalFirst + ", " + canonicalSecond}; !reflect.DeepEqual(messages, want) {
		t.Fatalf("resolved paths = %#v, want %#v", messages, want)
	}

	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{name: "missing member", path: "first.bin, missing.bin", want: "File does not exist"},
		{name: "directory", path: ".", want: "File is a folder"},
	} {
		t.Run(test.name, func(t *testing.T) {
			program := mustParse(t, filepath.Join(dir, test.name+".spec"), "x64:\nset \"%paths\" \""+test.path+"\"\nresolve \"%paths\"\npush $NULL\n")
			_, err := program.Run(capability, RunOptions{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Run() error = %v, want %q", err, test.want)
			}
		})
	}

	if runtime.GOOS != "windows" {
		unreadable := filepath.Join(dir, "unreadable.bin")
		if err := os.WriteFile(unreadable, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(unreadable, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })
		program := mustParse(t, filepath.Join(dir, "unreadable.spec"), "x64:\nset \"%path\" \"unreadable.bin\"\nresolve \"%path\"\npush $NULL\n")
		_, err := program.Run(capability, RunOptions{})
		if err == nil || !strings.Contains(err.Error(), "File is not readable") {
			t.Fatalf("Run() error = %v, want unreadable-file rejection", err)
		}
	}
}

func TestCallnearCanonicalizesSymlinkBeforeRuntime(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(realDir, "module.spec")
	if err := os.WriteFile(module, []byte("emit.x64:\n  push $NULL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	aliasDir := filepath.Join(dir, "alias")
	if err := os.Symlink(realDir, aliasDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	program := mustParse(t, filepath.Join(dir, "main.spec"), "x64:\n  callnear \"alias/module.spec\" \"emit\"\n")
	command := program.labels["x64"][0]
	canonical, err := filepath.EvalSymlinks(module)
	if err != nil {
		t.Fatal(err)
	}
	if got := command.RawArguments()[0]; command.Name() != "call" || got != canonical {
		t.Fatalf("callnear rewrite = %s %q, want call %q", command.Name(), got, canonical)
	}
	missing := mustParse(t, filepath.Join(dir, "missing-main.spec"), "x64:\n  callnear \"alias/missing.spec\" \"emit\"\n")
	canonicalRealDir, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := missing.labels["x64"][0].RawArguments()[0], filepath.Join(canonicalRealDir, "missing.spec"); got != want {
		t.Fatalf("missing callnear canonical path = %q, want %q", got, want)
	}
	if err := os.Remove(aliasDir); err != nil {
		t.Fatal(err)
	}
	capability, _ := None("x64")
	if _, err := program.Run(capability, RunOptions{}); err != nil {
		t.Fatalf("canonical callnear failed after symlink removal: %v", err)
	}
}

func TestCapabilityParsing(t *testing.T) {
	t.Parallel()
	coff := make([]byte, 20)
	coff[0], coff[1] = 0x64, 0x86
	capability, err := ParseCapability(coff)
	if err != nil {
		t.Fatal(err)
	}
	if capability.Arch != "x64" || capability.Label != "x64.o" || capability.Key != "$OBJECT" {
		t.Fatalf("capability = %#v", capability)
	}

	malformedSectionTable := make([]byte, 20)
	malformedSectionTable[0], malformedSectionTable[1] = 0x64, 0x86
	malformedSectionTable[2] = 1
	if _, err := ParseObject(malformedSectionTable); err == nil || !strings.Contains(err.Error(), "section table") {
		t.Fatalf("ParseObject malformed section table error = %v", err)
	}

	malformedSymbolTable := make([]byte, 20)
	malformedSymbolTable[0], malformedSymbolTable[1] = 0x4c, 0x01
	binary.LittleEndian.PutUint32(malformedSymbolTable[8:12], 20)
	binary.LittleEndian.PutUint32(malformedSymbolTable[12:16], 1)
	if _, err := ParseCapability(malformedSymbolTable); err == nil || !strings.Contains(err.Error(), "symbol table") {
		t.Fatalf("ParseCapability malformed symbol table error = %v", err)
	}

	arm64 := make([]byte, 20)
	binary.LittleEndian.PutUint16(arm64[:2], machineARM64)
	capability, err = ParseObject(arm64)
	if err != nil {
		t.Fatal(err)
	}
	if capability.Arch != "arm64" || capability.Label != "arm64.o" {
		t.Fatalf("ARM64 object capability = %#v", capability)
	}
	if _, err := ParseCapability(arm64); err == nil {
		t.Fatal("ParseCapability accepted ARM64 despite upstream x86/x64 detection contract")
	}
}

func TestRuntimeMetadataDoesNotMutateParsedSpec(t *testing.T) {
	t.Parallel()
	s := mustParse(t, "meta.spec", "name \"Static\"\nx64:\n  meta name \"Runtime\"\n  push $NULL\n")
	capability, _ := None("x64")
	if _, err := s.Run(capability, RunOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, want := s.Metadata().Name, "Static"; got != want {
		t.Fatalf("metadata name after Run = %q, want %q", got, want)
	}
}

func TestParsedSpecCanRunConcurrently(t *testing.T) {
	t.Parallel()
	s := mustParse(t, "parallel.spec", "x64:\n  push $DATA\n")
	capability, _ := None("x64")
	var wait sync.WaitGroup
	errors := make(chan error, 32)
	for value := byte(0); value < 32; value++ {
		value := value
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, err := s.Run(capability, RunOptions{Environment: Environment{"$DATA": []byte{value}}})
			if err != nil {
				errors <- err
				return
			}
			if !bytes.Equal(got, []byte{value}) {
				errors <- &testError{got: got, want: []byte{value}}
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

type testError struct{ got, want []byte }

func (e *testError) Error() string { return "concurrent Run returned unexpected bytes" }

func mustParse(t *testing.T, file, content string) *Spec {
	t.Helper()
	s, err := Parse(file, content)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
