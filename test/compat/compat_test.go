//go:build compat

// SPDX-License-Identifier: GPL-3.0-only

package compat_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const (
	palaceJAREnv = "CRYSTAL_PALACE_JAR"
	grottoBinEnv = "CRYSTAL_GROTTO_BIN"
)

func TestDeterministicCompatibility(t *testing.T) {
	palaceJAR := requireArtifact(t, palaceJAREnv, false)
	grottoBin := requireArtifact(t, grottoBinEnv, true)
	java, err := exec.LookPath("java")
	if err != nil {
		t.Fatalf("compat build tag requires java in PATH: %v", err)
	}
	root := repositoryRoot(t)
	fixtures := filepath.Join(root, "testdata", "modules")

	for _, test := range compatibilityCases(t, fixtures) {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			workDir := t.TempDir()
			grottoOutput := filepath.Join(workDir, "grotto.bin")
			palaceOutput := filepath.Join(workDir, "palace.bin")
			grottoArgs := append([]string{"build", test.specPath, test.arch, grottoOutput}, test.extraArgs...)
			palaceArgs := append([]string{"-jar", palaceJAR, "build", test.specPath, test.arch, palaceOutput}, test.extraArgs...)

			grottoStdout, grottoStderr, err := run(grottoBin, workDir, grottoArgs...)
			if err != nil {
				t.Fatalf("Crystal Grotto failed: %v\nstdout:\n%s\nstderr:\n%s", err, grottoStdout, grottoStderr)
			}
			palaceStdout, palaceStderr, err := run(java, workDir, palaceArgs...)
			if err != nil {
				t.Fatalf("Crystal Palace failed: %v\nstdout:\n%s\nstderr:\n%s", err, palaceStdout, palaceStderr)
			}

			// These successful deterministic fixtures are quiet upstream. Compare
			// streams byte-for-byte; no whitespace or diagnostic normalization is
			// appropriate here.
			if !bytes.Equal(grottoStdout, palaceStdout) || !bytes.Equal(grottoStderr, palaceStderr) {
				t.Fatalf("process output differs\nGrotto stdout: %q\nPalace stdout: %q\nGrotto stderr: %q\nPalace stderr: %q",
					grottoStdout, palaceStdout, grottoStderr, palaceStderr)
			}

			grottoBytes := readOutput(t, grottoOutput)
			palaceBytes := readOutput(t, palaceOutput)
			if !bytes.Equal(grottoBytes, test.want) {
				t.Fatalf("Crystal Grotto output = %x, want %x", grottoBytes, test.want)
			}
			if !bytes.Equal(palaceBytes, test.want) {
				t.Fatalf("Crystal Palace output = %x, want %x", palaceBytes, test.want)
			}
			if !bytes.Equal(grottoBytes, palaceBytes) {
				t.Fatalf("binary output differs\nGrotto: %x\nPalace: %x", grottoBytes, palaceBytes)
			}
		})
	}
}

func TestMinGWCOFFCompatibility(t *testing.T) {
	palaceJAR := requireArtifact(t, palaceJAREnv, false)
	grottoBin := requireArtifact(t, grottoBinEnv, true)
	java, err := exec.LookPath("java")
	if err != nil {
		t.Fatalf("compat build tag requires java in PATH: %v", err)
	}
	root := repositoryRoot(t)
	fixtureRoot := filepath.Join(root, "testdata", "modules", "coff")
	for _, test := range []struct {
		name     string
		compiler string
		source   string
		spec     string
		want     []byte
	}{
		{name: "x86", compiler: "i686-w64-mingw32-gcc", source: "basic.x86.S", spec: "pic.spec", want: []byte{0xb8, 0x2a, 0, 0, 0, 0xc3, 0x90, 0x90}},
		{name: "x64", compiler: "x86_64-w64-mingw32-gcc", source: "basic.x64.S", spec: "pic.spec", want: []byte{0xb8, 0x2a, 0, 0, 0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}},
		{name: "x64_relax", compiler: "x86_64-w64-mingw32-gcc", source: "relax.x64.S", spec: "relax.spec"},
		{name: "x64_fixbss", compiler: "x86_64-w64-mingw32-gcc", source: "fixbss.x64.S", spec: "fixbss.spec"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			compiler, err := exec.LookPath(test.compiler)
			if err != nil {
				t.Fatalf("compat build tag requires %s in PATH: %v", test.compiler, err)
			}
			workDir := t.TempDir()
			objectPath := filepath.Join(workDir, "basic.o")
			compile := exec.Command(compiler, "-c", "-o", objectPath, filepath.Join(fixtureRoot, test.source))
			compile.Dir = workDir
			if output, err := compile.CombinedOutput(); err != nil {
				t.Fatalf("compile COFF fixture: %v\n%s", err, output)
			}

			grottoOutput := filepath.Join(workDir, "grotto.pic")
			palaceOutput := filepath.Join(workDir, "palace.pic")
			specPath := filepath.Join(fixtureRoot, test.spec)
			grottoStdout, grottoStderr, err := run(grottoBin, workDir, "link", specPath, objectPath, grottoOutput)
			if err != nil {
				t.Fatalf("Crystal Grotto failed: %v\nstdout:\n%s\nstderr:\n%s", err, grottoStdout, grottoStderr)
			}
			palaceStdout, palaceStderr, err := run(java, workDir, "-jar", palaceJAR, "link", specPath, objectPath, palaceOutput)
			if err != nil {
				t.Fatalf("Crystal Palace failed: %v\nstdout:\n%s\nstderr:\n%s", err, palaceStdout, palaceStderr)
			}
			if !bytes.Equal(grottoStdout, palaceStdout) || !bytes.Equal(grottoStderr, palaceStderr) {
				t.Fatalf("process output differs\nGrotto stdout: %q\nPalace stdout: %q\nGrotto stderr: %q\nPalace stderr: %q",
					grottoStdout, palaceStdout, grottoStderr, palaceStderr)
			}

			grottoBytes := readOutput(t, grottoOutput)
			palaceBytes := readOutput(t, palaceOutput)
			if test.want != nil && !bytes.Equal(grottoBytes, test.want) {
				t.Fatalf("Crystal Grotto PIC = %x, want %x", grottoBytes, test.want)
			}
			if test.want != nil && !bytes.Equal(palaceBytes, test.want) {
				t.Fatalf("Crystal Palace PIC = %x, want %x", palaceBytes, test.want)
			}
			if !bytes.Equal(grottoBytes, palaceBytes) {
				t.Fatalf("binary output differs\nGrotto: %x\nPalace: %x", grottoBytes, palaceBytes)
			}
		})
	}
}

func TestYARAGenerationCompatibility(t *testing.T) {
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
	root := repositoryRoot(t)
	fixtures := filepath.Join(root, "testdata", "modules", "coff")
	workDir := t.TempDir()
	objectPath := filepath.Join(workDir, "rulegen.x64.o")
	compile := exec.Command(compiler, "-c", "-o", objectPath, filepath.Join(fixtures, "rulegen.x64.S"))
	compile.Dir = workDir
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile YARA COFF fixture: %v\n%s", err, output)
	}

	specPath := filepath.Join(fixtures, "rulegen.spec")
	grottoOutput, palaceOutput := filepath.Join(workDir, "grotto.pic"), filepath.Join(workDir, "palace.pic")
	grottoRules, palaceRules := filepath.Join(workDir, "grotto.yar"), filepath.Join(workDir, "palace.yar")
	grottoStdout, grottoStderr, err := run(grottoBin, workDir, "link", specPath, objectPath, grottoOutput, "-g", grottoRules)
	if err != nil {
		t.Fatalf("Crystal Grotto YARA generation failed: %v\nstdout:\n%s\nstderr:\n%s", err, grottoStdout, grottoStderr)
	}
	palaceStdout, palaceStderr, err := run(java, workDir, "-jar", palaceJAR, "link", specPath, objectPath, palaceOutput, "-g", palaceRules)
	if err != nil {
		t.Fatalf("Crystal Palace YARA generation failed: %v\nstdout:\n%s\nstderr:\n%s", err, palaceStdout, palaceStderr)
	}
	if !bytes.Equal(grottoStdout, palaceStdout) || !bytes.Equal(grottoStderr, palaceStderr) {
		t.Fatalf("YARA process output differs\nGrotto stdout: %q\nPalace stdout: %q\nGrotto stderr: %q\nPalace stderr: %q",
			grottoStdout, palaceStdout, grottoStderr, palaceStderr)
	}
	if got, want := readOutput(t, grottoOutput), readOutput(t, palaceOutput); !bytes.Equal(got, want) {
		t.Fatalf("YARA fixture program differs\nGrotto: %x\nPalace: %x", got, want)
	}
	grottoSemantic := parseYARASemantics(t, readOutput(t, grottoRules))
	palaceSemantic := parseYARASemantics(t, readOutput(t, palaceRules))
	if !reflect.DeepEqual(grottoSemantic, palaceSemantic) {
		t.Fatalf("YARA semantics differ\nGrotto: %#v\nPalace: %#v\n\nGrotto YARA:\n%s\nPalace YARA:\n%s",
			grottoSemantic, palaceSemantic, readOutput(t, grottoRules), readOutput(t, palaceRules))
	}
}

func TestDFRSemanticCompatibility(t *testing.T) {
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
	root := repositoryRoot(t)
	fixtures := filepath.Join(root, "testdata", "modules", "coff")
	workDir := t.TempDir()
	objectPath := filepath.Join(workDir, "dfr.x64.o")
	compile := exec.Command(compiler, "-c", "-o", objectPath, filepath.Join(fixtures, "dfr.x64.S"))
	compile.Dir = workDir
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile DFR COFF fixture: %v\n%s", err, output)
	}

	specPath := filepath.Join(fixtures, "dfr.spec")
	grottoOutput, palaceOutput := filepath.Join(workDir, "grotto.pic"), filepath.Join(workDir, "palace.pic")
	grottoStdout, grottoStderr, err := run(grottoBin, workDir, "link", specPath, objectPath, grottoOutput)
	if err != nil {
		t.Fatalf("Crystal Grotto DFR failed: %v\nstdout:\n%s\nstderr:\n%s", err, grottoStdout, grottoStderr)
	}
	palaceStdout, palaceStderr, err := run(java, workDir, "-jar", palaceJAR, "link", specPath, objectPath, palaceOutput)
	if err != nil {
		t.Fatalf("Crystal Palace DFR failed: %v\nstdout:\n%s\nstderr:\n%s", err, palaceStdout, palaceStderr)
	}
	if !bytes.Equal(grottoStdout, palaceStdout) || !bytes.Equal(grottoStderr, palaceStderr) {
		t.Fatalf("DFR process output differs\nGrotto stdout: %q\nPalace stdout: %q\nGrotto stderr: %q\nPalace stderr: %q",
			grottoStdout, palaceStdout, grottoStderr, palaceStderr)
	}
	if runtime.GOARCH != "amd64" {
		t.Logf("generated both DFR programs; execution check requires an amd64 host (running %s)", runtime.GOARCH)
		return
	}
	hostCompiler, err := exec.LookPath("cc")
	if err != nil {
		t.Fatalf("compat build tag requires a host C compiler in PATH: %v", err)
	}

	runnerSource := filepath.Join(workDir, "runpic.c")
	if err := os.WriteFile(runnerSource, []byte(picRunnerSource), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := filepath.Join(workDir, "runpic")
	hostArgs := []string{"-O2", "-Wall", "-Wextra", "-Werror"}
	if runtime.GOOS == "darwin" {
		hostArgs = append(hostArgs, "-arch", "x86_64")
	}
	hostArgs = append(hostArgs, "-o", runner, runnerSource)
	hostBuild := exec.Command(hostCompiler, hostArgs...)
	if output, err := hostBuild.CombinedOutput(); err != nil {
		t.Fatalf("compile PIC runner: %v\n%s", err, output)
	}
	for _, generated := range []struct {
		name string
		path string
	}{
		{name: "Crystal Grotto", path: grottoOutput},
		{name: "Crystal Palace", path: palaceOutput},
	} {
		stdout, stderr, err := run(runner, workDir, generated.path)
		if err != nil {
			t.Fatalf("execute %s DFR PIC: %v\nstdout:\n%s\nstderr:\n%s", generated.name, err, stdout, stderr)
		}
		if string(stdout) != "42\n" || len(stderr) != 0 {
			t.Fatalf("%s DFR PIC result: stdout=%q stderr=%q", generated.name, stdout, stderr)
		}
	}
}

const picRunnerSource = `#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

int main(int argc, char **argv) {
	if (argc != 2) return 64;
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) return 65;
	struct stat info;
	if (fstat(fd, &info) != 0 || info.st_size <= 0) return 66;
	size_t size = (size_t)info.st_size;
	void *code = mmap(NULL, size, PROT_READ | PROT_WRITE,
	                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (code == MAP_FAILED) return 67;
	size_t offset = 0;
	while (offset < size) {
		ssize_t count = read(fd, (unsigned char *)code + offset, size - offset);
		if (count <= 0) return 68;
		offset += (size_t)count;
	}
	close(fd);
	if (mprotect(code, size, PROT_READ | PROT_EXEC) != 0) return 69;
	__builtin___clear_cache((char *)code, (char *)code + size);
	int (*entry)(void) = (int (*)(void))code;
	int result = entry();
	printf("%d\n", result);
	return 0;
}
`

type yaraSemantics struct {
	Metadata   []string
	Signatures []string
	Condition  []string
}

func parseYARASemantics(t *testing.T, content []byte) yaraSemantics {
	t.Helper()
	result := yaraSemantics{}
	section := ""
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		switch line {
		case "meta:":
			section = "meta"
			continue
		case "strings:":
			section = "strings"
			continue
		case "condition:":
			section = "condition"
			continue
		}
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") ||
			strings.HasPrefix(line, "*") || line == "}" || strings.HasPrefix(line, "rule ") {
			continue
		}
		switch section {
		case "meta":
			if strings.HasPrefix(line, "date = ") {
				continue
			}
			result.Metadata = append(result.Metadata, line)
		case "strings":
			separator := strings.Index(line, "=")
			if !strings.HasPrefix(line, "$") || separator < 0 {
				t.Fatalf("cannot parse YARA signature line %q", line)
			}
			result.Signatures = append(result.Signatures, strings.TrimSpace(line[separator+1:]))
		case "condition":
			result.Condition = append(result.Condition, line)
		}
	}
	sort.Strings(result.Metadata)
	sort.Strings(result.Signatures)
	if len(result.Signatures) == 0 || len(result.Condition) == 0 {
		t.Fatalf("YARA output has no signatures or condition:\n%s", content)
	}
	return result
}

type compatibilityCase struct {
	name      string
	specPath  string
	arch      string
	extraArgs []string
	want      []byte
}

func compatibilityCases(t *testing.T, root string) []compatibilityCase {
	t.Helper()
	decode := func(value string) []byte {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatalf("decode expected fixture bytes: %v", err)
		}
		return decoded
	}
	config := "@" + filepath.Join(root, "config.spec")
	return []compatibilityCase{
		{name: "passthrough_x86", specPath: filepath.Join(root, "passthrough.spec"), arch: "x86", extraArgs: []string{"PAYLOAD=000102feff"}, want: decode("000102feff")},
		{name: "passthrough_x64", specPath: filepath.Join(root, "passthrough.spec"), arch: "x64", extraArgs: []string{"$PAYLOAD=000102feff"}, want: decode("000102feff")},
		{name: "pack_x86", specPath: filepath.Join(root, "pack.spec"), arch: "x86", want: decode("7f3412efcdab890807060504030201443322114869410042000000deadbeef00")},
		{name: "pack_x64", specPath: filepath.Join(root, "pack.spec"), arch: "x64", want: decode("7f3412efcdab89080706050403020144332211000000004869410042000000deadbeef00")},
		{name: "transform_x86", specPath: filepath.Join(root, "transform.spec"), arch: "x86", want: decode("050000000f1f2d3d4b")},
		{name: "transform_x64", specPath: filepath.Join(root, "transform.spec"), arch: "x64", want: decode("050000000f1f2d3d4b")},
		{name: "config_and_call_x86", specPath: filepath.Join(root, "main.spec"), arch: "x86", extraArgs: []string{config}, want: decode("cafe67726f74746f00")},
		{name: "config_and_call_x64", specPath: filepath.Join(root, "main.spec"), arch: "x64", extraArgs: []string{config}, want: decode("cafe67726f74746f00")},
	}
}

func requireArtifact(t *testing.T, envName string, executable bool) string {
	t.Helper()
	path := os.Getenv(envName)
	if path == "" {
		t.Fatalf("compat build tag requires %s to name a built artifact", envName)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve %s=%q: %v", envName, path, err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		t.Fatalf("stat %s=%q: %v", envName, absolute, err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%s=%q is not a regular file", envName, absolute)
	}
	if executable && runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s=%q is not executable", envName, absolute)
	}
	return absolute
}

func run(path, workDir string, args ...string) (stdout, stderr []byte, err error) {
	command := exec.Command(path, args...)
	command.Dir = workDir
	var stdoutBuffer, stderrBuffer bytes.Buffer
	command.Stdout = &stdoutBuffer
	command.Stderr = &stderrBuffer
	err = command.Run()
	return stdoutBuffer.Bytes(), stderrBuffer.Bytes(), err
}

func readOutput(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("determine compatibility source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("locate repository root from %s: %v", currentFile, err)
	}
	return root
}

// normalizeDiagnostic is intentionally narrow and is reserved for diagnostic
// compatibility cases: it replaces only exact product/command names and exact
// absolute paths supplied by the caller. It does not trim or rewrite general
// whitespace. Deterministic success cases above require raw equality.
func normalizeDiagnostic(data []byte, replacements map[string]string) []byte {
	text := string(data)
	text = strings.ReplaceAll(text, "Crystal Palace", "Crystal PRODUCT")
	text = strings.ReplaceAll(text, "Crystal Grotto", "Crystal PRODUCT")
	text = strings.ReplaceAll(text, "crystal-grotto", "cpl")
	for actual, replacement := range replacements {
		text = strings.ReplaceAll(text, actual, replacement)
	}
	return []byte(text)
}

func TestNormalizeDiagnosticIsNarrow(t *testing.T) {
	input := []byte("Crystal Grotto /tmp/one  keep  spaces\n")
	got := normalizeDiagnostic(input, map[string]string{"/tmp/one": "<WORK>"})
	want := []byte("Crystal PRODUCT <WORK>  keep  spaces\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("normalizeDiagnostic = %q, want %q", got, want)
	}
}
