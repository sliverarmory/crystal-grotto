//go:build compat

// SPDX-License-Identifier: GPL-3.0-only

package compat_test

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

// TestRandomizedStructuralCompatibility compares process-level compatibility
// rather than randomized bytes. Each implementation must accept the same real
// MinGW COFF input, remain quiet on success, emit a structurally valid x64 PIC,
// and preserve the fixture's observable return value.
func TestRandomizedStructuralCompatibility(t *testing.T) {
	palaceJAR := requireArtifact(t, palaceJAREnv, false)
	grottoBin := requireArtifact(t, grottoBinEnv, true)
	java, err := exec.LookPath("java")
	if err != nil {
		t.Fatalf("compat build tag requires java in PATH: %v", err)
	}
	compiler, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Fatalf("compat build tag requires x86_64-w64-mingw32-gcc in PATH: %v", err)
	}

	fixtureRoot := filepath.Join(repositoryRoot(t), "testdata", "modules", "structural")
	workDir := t.TempDir()
	objectPath := filepath.Join(workDir, "structural.x64.o")
	compile := exec.Command(compiler, "-c", "-o", objectPath, filepath.Join(fixtureRoot, "structural.x64.S"))
	compile.Dir = workDir
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile structural COFF fixture: %v\n%s", err, output)
	}

	for _, test := range []struct {
		name string
		spec string
	}{
		{name: "blockparty", spec: "blockparty.spec"},
		{name: "shatter", spec: "shatter.spec"},
		{name: "mutate_regdance", spec: "mutate-regdance.spec"},
	} {
		t.Run(test.name, func(t *testing.T) {
			grottoOutput := filepath.Join(workDir, test.name+"-grotto.pic")
			palaceOutput := filepath.Join(workDir, test.name+"-palace.pic")
			specPath := filepath.Join(fixtureRoot, test.spec)

			grottoStdout, grottoStderr, err := run(grottoBin, workDir, "link", specPath, objectPath, grottoOutput)
			if err != nil {
				t.Fatalf("Crystal Grotto structural transform failed: %v\nstdout:\n%s\nstderr:\n%s", err, grottoStdout, grottoStderr)
			}
			palaceStdout, palaceStderr, err := run(java, workDir, "-jar", palaceJAR, "link", specPath, objectPath, palaceOutput)
			if err != nil {
				t.Fatalf("Crystal Palace structural transform failed: %v\nstdout:\n%s\nstderr:\n%s", err, palaceStdout, palaceStderr)
			}
			if !bytes.Equal(grottoStdout, palaceStdout) || !bytes.Equal(grottoStderr, palaceStderr) {
				t.Fatalf("structural-transform success streams differ\nGrotto stdout: %q\nPalace stdout: %q\nGrotto stderr: %q\nPalace stderr: %q",
					grottoStdout, palaceStdout, grottoStderr, palaceStderr)
			}

			validateX64PICStructure(t, "Crystal Grotto", readOutput(t, grottoOutput))
			validateX64PICStructure(t, "Crystal Palace", readOutput(t, palaceOutput))
			executePICOutputs(t, workDir, []picExecution{
				{name: "Crystal Grotto " + test.name, path: grottoOutput},
				{name: "Crystal Palace " + test.name, path: palaceOutput},
			})
		})
	}
}

func validateX64PICStructure(t *testing.T, implementation string, image []byte) {
	t.Helper()
	if len(image) == 0 {
		t.Fatalf("%s emitted an empty PIC", implementation)
	}
	ctx := context.Background()
	decoder, err := x86.NewCapstone(ctx, x86.Mode64)
	if err != nil {
		t.Fatalf("open x64 decoder for %s PIC: %v", implementation, err)
	}
	defer func() {
		if err := decoder.Close(ctx); err != nil {
			t.Errorf("close x64 decoder for %s PIC: %v", implementation, err)
		}
	}()
	instructions, err := decoder.Disassemble(ctx, image, 0)
	if err != nil {
		t.Fatalf("decode complete %s PIC: %v", implementation, err)
	}
	for _, instruction := range instructions {
		if strings.EqualFold(instruction.Mnemonic, "ret") {
			return
		}
	}
	t.Fatalf("%s PIC contains no return instruction", implementation)
}
