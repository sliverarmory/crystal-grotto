// SPDX-License-Identifier: GPL-3.0-only

package spec

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
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
