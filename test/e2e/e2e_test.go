// SPDX-License-Identifier: GPL-3.0-only

package e2e_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var (
	repositoryRoot string
	fixtureRoot    string
	commandPath    string
	commandTemp    string
)

func TestMain(m *testing.M) {
	var err error
	repositoryRoot, err = findRepositoryRoot()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fixtureRoot = filepath.Join(repositoryRoot, "testdata", "modules")
	commandTemp, err = os.MkdirTemp("", "crystal-grotto-e2e-")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create E2E temporary directory: %v\n", err)
		os.Exit(1)
	}

	commandPath = filepath.Join(commandTemp, executableName("crystal-grotto"))
	build := exec.Command("go", "build", "-trimpath", "-o", commandPath, "./cmd/crystal-grotto")
	build.Dir = repositoryRoot
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build Crystal Grotto CLI: %v\n%s", buildErr, output)
		os.Exit(1)
	}

	exitCode := m.Run()
	if removeErr := os.RemoveAll(commandTemp); removeErr != nil && exitCode == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "remove E2E temporary directory: %v\n", removeErr)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func TestBuildModules(t *testing.T) {
	t.Parallel()
	tests := deterministicCases(t, fixtureRoot)
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			workDir := t.TempDir()
			outputPath := filepath.Join(workDir, "output.bin")
			args := append([]string{"build", test.specPath, test.arch, outputPath}, test.extraArgs...)
			stdout, stderr, err := runCommand(commandPath, workDir, args...)
			if err != nil {
				t.Fatalf("crystal-grotto %s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), err, stdout, stderr)
			}
			if len(stdout) != 0 || len(stderr) != 0 {
				t.Fatalf("successful build was not quiet\nstdout: %q\nstderr: %q", stdout, stderr)
			}
			got, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("read output: %v", err)
			}
			if !bytes.Equal(got, test.want) {
				t.Fatalf("output = %x, want %x", got, test.want)
			}
		})
	}
}

type deterministicCase struct {
	name      string
	specPath  string
	arch      string
	extraArgs []string
	want      []byte
}

func deterministicCases(t *testing.T, root string) []deterministicCase {
	t.Helper()
	decode := func(value string) []byte {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatalf("decode expected fixture bytes: %v", err)
		}
		return decoded
	}
	config := "@" + filepath.Join(root, "config.spec")
	return []deterministicCase{
		{
			name:      "passthrough_x86",
			specPath:  filepath.Join(root, "passthrough.spec"),
			arch:      "x86",
			extraArgs: []string{"PAYLOAD=000102feff"},
			want:      decode("000102feff"),
		},
		{
			name:      "passthrough_x64",
			specPath:  filepath.Join(root, "passthrough.spec"),
			arch:      "x64",
			extraArgs: []string{"$PAYLOAD=000102feff"},
			want:      decode("000102feff"),
		},
		{
			name:     "pack_x86",
			specPath: filepath.Join(root, "pack.spec"),
			arch:     "x86",
			want:     decode("7f3412efcdab890807060504030201443322114869410042000000deadbeef00"),
		},
		{
			name:     "pack_x64",
			specPath: filepath.Join(root, "pack.spec"),
			arch:     "x64",
			want:     decode("7f3412efcdab89080706050403020144332211000000004869410042000000deadbeef00"),
		},
		{
			name:     "transform_x86",
			specPath: filepath.Join(root, "transform.spec"),
			arch:     "x86",
			want:     decode("050000000f1f2d3d4b"),
		},
		{
			name:     "transform_x64",
			specPath: filepath.Join(root, "transform.spec"),
			arch:     "x64",
			want:     decode("050000000f1f2d3d4b"),
		},
		{
			name:      "config_and_call_x86",
			specPath:  filepath.Join(root, "main.spec"),
			arch:      "x86",
			extraArgs: []string{config},
			want:      decode("cafe67726f74746f00"),
		},
		{
			name:      "config_and_call_x64",
			specPath:  filepath.Join(root, "main.spec"),
			arch:      "x64",
			extraArgs: []string{config},
			want:      decode("cafe67726f74746f00"),
		},
	}
}

func runCommand(path, workDir string, args ...string) (stdout, stderr []byte, err error) {
	command := exec.Command(path, args...)
	command.Dir = workDir
	var stdoutBuffer, stderrBuffer bytes.Buffer
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer
	err = command.Run()
	return stdoutBuffer.Bytes(), stderrBuffer.Bytes(), err
}

func findRepositoryRoot() (string, error) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("determine E2E source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("locate repository root from %s: %w", currentFile, err)
	}
	return root, nil
}

func executableName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}
