//go:build compat

// SPDX-License-Identifier: GPL-3.0-only

package compat_test

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestOrderingLTOCompatibility(t *testing.T) {
	palaceJAR := requireArtifact(t, palaceJAREnv, false)
	grottoBin := requireArtifact(t, grottoBinEnv, true)
	java, err := exec.LookPath("java")
	if err != nil {
		t.Fatalf("compat build tag requires java in PATH: %v", err)
	}
	fixtureRoot := filepath.Join(repositoryRoot(t), "testdata", "modules", "ordering")

	for _, test := range []struct {
		name     string
		compiler string
		source   string
		spec     string
		want     []byte
	}{
		{
			name:     "optimize_x86",
			compiler: "i686-w64-mingw32-gcc",
			source:   "optimize.x86.S",
			spec:     "optimize.spec",
			want:     []byte{0xe8, 0x01, 0, 0, 0, 0xc3, 0xb8, 42, 0, 0, 0, 0xc3},
		},
		{
			name:     "optimize_x64",
			compiler: "x86_64-w64-mingw32-gcc",
			source:   "optimize.x64.S",
			spec:     "optimize.spec",
			want:     []byte{0xe8, 0x01, 0, 0, 0, 0xc3, 0xb8, 42, 0, 0, 0, 0xc3},
		},
		{
			name:     "gofirst_x86",
			compiler: "i686-w64-mingw32-gcc",
			source:   "gofirst.x86.S",
			spec:     "gofirst.spec",
			want: []byte{
				0xe8, 0x03, 0, 0, 0, 0xc3, 0x90, 0xcc,
				0xb8, 42, 0, 0, 0, 0xc3, 0x90, 0xcc,
				0xb8, 7, 0, 0, 0, 0xc3, 0x90, 0xcc,
			},
		},
		{
			name:     "gofirst_x64",
			compiler: "x86_64-w64-mingw32-gcc",
			source:   "gofirst.x64.S",
			spec:     "gofirst.spec",
			want: []byte{
				0xe8, 0x03, 0, 0, 0, 0xc3, 0x90, 0xcc,
				0xb8, 42, 0, 0, 0, 0xc3, 0x90, 0xcc,
				0xb8, 7, 0, 0, 0, 0xc3, 0x90, 0xcc,
				0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			compiler, err := exec.LookPath(test.compiler)
			if err != nil {
				t.Fatalf("compat build tag requires %s in PATH: %v", test.compiler, err)
			}
			workDir := t.TempDir()
			objectPath := compileOrderingCOFF(t, compiler, workDir, filepath.Join(fixtureRoot, test.source))
			grottoOutput, palaceOutput := runOrderingLink(t, grottoBin, java, palaceJAR, workDir,
				filepath.Join(fixtureRoot, test.spec), objectPath)

			grottoBytes := readOutput(t, grottoOutput)
			palaceBytes := readOutput(t, palaceOutput)
			if !bytes.Equal(grottoBytes, palaceBytes) {
				t.Fatalf("ordering output differs\nGrotto: %x\nPalace: %x", grottoBytes, palaceBytes)
			}
			if test.want != nil && !bytes.Equal(grottoBytes, test.want) {
				t.Fatalf("ordering output = %x, want %x", grottoBytes, test.want)
			}
		})
	}
}

func TestDiscoPreservesPICEntryCompatibility(t *testing.T) {
	palaceJAR := requireArtifact(t, palaceJAREnv, false)
	grottoBin := requireArtifact(t, grottoBinEnv, true)
	java, err := exec.LookPath("java")
	if err != nil {
		t.Fatalf("compat build tag requires java in PATH: %v", err)
	}
	fixtureRoot := filepath.Join(repositoryRoot(t), "testdata", "modules", "ordering")

	for _, test := range []struct {
		name     string
		compiler string
		source   string
		execute  bool
	}{
		{name: "x86", compiler: "i686-w64-mingw32-gcc", source: "disco.x86.S"},
		{name: "x64", compiler: "x86_64-w64-mingw32-gcc", source: "disco.x64.S", execute: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			compiler, err := exec.LookPath(test.compiler)
			if err != nil {
				t.Fatalf("compat build tag requires %s in PATH: %v", test.compiler, err)
			}
			workDir := t.TempDir()
			objectPath := compileOrderingCOFF(t, compiler, workDir, filepath.Join(fixtureRoot, test.source))
			grottoOutput, palaceOutput := runOrderingLink(t, grottoBin, java, palaceJAR, workDir,
				filepath.Join(fixtureRoot, "disco.spec"), objectPath)

			grottoSemantics := discoSemanticsFor(t, readOutput(t, grottoOutput))
			palaceSemantics := discoSemanticsFor(t, readOutput(t, palaceOutput))
			if grottoSemantics != palaceSemantics {
				t.Fatalf("disco structure differs: Grotto=%+v Palace=%+v", grottoSemantics, palaceSemantics)
			}
			if test.execute {
				executePICOutputs(t, workDir, []picExecution{
					{name: "Crystal Grotto +disco", path: grottoOutput},
					{name: "Crystal Palace +disco", path: palaceOutput},
				})
			}
		})
	}
}

type discoSemantics struct {
	size            int
	functionMarkers int
	entryReturns    int32
}

func discoSemanticsFor(t *testing.T, data []byte) discoSemantics {
	t.Helper()
	if len(data) < 12 || data[0] != 0xe8 || data[5] != 0xc3 {
		t.Fatalf("+disco PIC does not keep call/ret entry at offset zero: %x", data)
	}
	target := int64(5) + int64(int32(binary.LittleEndian.Uint32(data[1:5])))
	if target < 0 || target+6 > int64(len(data)) {
		t.Fatalf("+disco entry call target %d is outside %d-byte PIC", target, len(data))
	}
	targetCode := data[target : target+6]
	if !bytes.Equal(targetCode, []byte{0xb8, 42, 0, 0, 0, 0xc3}) {
		t.Fatalf("+disco entry target = %x, want helper returning 42", targetCode)
	}
	markers := 0
	for _, value := range []byte{1, 2, 42} {
		if count := bytes.Count(data, []byte{0xb8, value, 0, 0, 0, 0xc3}); count != 1 {
			t.Fatalf("+disco PIC contains %d marker functions returning %d, want 1: %x", count, value, data)
		}
		markers++
	}
	return discoSemantics{size: len(data), functionMarkers: markers, entryReturns: 42}
}

func compileOrderingCOFF(t *testing.T, compiler, workDir, source string) string {
	t.Helper()
	objectPath := filepath.Join(workDir, "ordering.o")
	command := exec.Command(compiler, "-c", "-o", objectPath, source)
	command.Dir = workDir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile ordering COFF fixture: %v\n%s", err, output)
	}
	raw, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatalf("read ordering COFF fixture: %v", err)
	}
	object, err := coff.Parse(raw)
	if err != nil {
		t.Fatalf("parse ordering COFF fixture: %v", err)
	}
	text := object.GetSection(".text")
	if text == nil {
		t.Fatal("ordering COFF fixture has no .text section")
	}
	if len(text.Relocations) != 0 {
		t.Fatalf("ordering COFF fixture has %d .text relocations; want a relocation-free same-section direct call", len(text.Relocations))
	}
	return objectPath
}

func runOrderingLink(t *testing.T, grottoBin, java, palaceJAR, workDir, specPath, objectPath string) (string, string) {
	t.Helper()
	grottoOutput := filepath.Join(workDir, "grotto.pic")
	palaceOutput := filepath.Join(workDir, "palace.pic")
	grottoStdout, grottoStderr, err := run(grottoBin, workDir, "link", specPath, objectPath, grottoOutput)
	if err != nil {
		t.Fatalf("Crystal Grotto ordering link failed: %v\nstdout:\n%s\nstderr:\n%s", err, grottoStdout, grottoStderr)
	}
	palaceStdout, palaceStderr, err := run(java, workDir, "-jar", palaceJAR, "link", specPath, objectPath, palaceOutput)
	if err != nil {
		t.Fatalf("Crystal Palace ordering link failed: %v\nstdout:\n%s\nstderr:\n%s", err, palaceStdout, palaceStderr)
	}
	if !bytes.Equal(grottoStdout, palaceStdout) || !bytes.Equal(grottoStderr, palaceStderr) {
		t.Fatalf("ordering process output differs\nGrotto stdout: %q\nPalace stdout: %q\nGrotto stderr: %q\nPalace stderr: %q",
			grottoStdout, palaceStdout, grottoStderr, palaceStderr)
	}
	return grottoOutput, palaceOutput
}
