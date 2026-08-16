// SPDX-License-Identifier: GPL-3.0-only

package resolver

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestParseImportMatchesUpstreamSpellings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		symbol   string
		valid    bool
		module   string
		function string
		target   string
	}{
		{symbol: "Sleep"},
		{symbol: "__imp_KERNEL32$Sleep", valid: true, module: "KERNEL32", function: "Sleep", target: "KERNEL32$Sleep"},
		{symbol: "__imp__WS2_32$connect@12", valid: true, module: "WS2_32", function: "connect", target: "WS2_32$connect"},
		{symbol: "__imp_GetProcAddress", valid: true, function: "GetProcAddress", target: "$GetProcAddress"},
		{symbol: "__imp_MOD$func@8@extra", valid: true, module: "MOD", function: "func@8@extra", target: "MOD$func@8@extra"},
		{symbol: "__imp_MOD$one$two", valid: true, function: "MOD$one$two", target: "$MOD$one$two"},
		{symbol: "__imp_MOD$", valid: true, function: "MOD$", target: "$MOD$"},
		{symbol: "__imp_", valid: true, function: "", target: "$"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.symbol, func(t *testing.T) {
			t.Parallel()
			imported, valid := ParseImport(test.symbol)
			if valid != test.valid || imported.Valid != test.valid || imported.Module != test.module || imported.Function != test.function {
				t.Fatalf("ParseImport(%q) = %#v, %t", test.symbol, imported, valid)
			}
			if valid && imported.Target() != test.target {
				t.Fatalf("Target() = %q, want %q", imported.Target(), test.target)
			}
		})
	}
}

func TestImportModulePopulationAndHashes(t *testing.T) {
	t.Parallel()
	for _, function := range []string{"GetProcAddress", "LoadLibraryA"} {
		imported, ok := ParseImport("__imp_" + function)
		if !ok {
			t.Fatal("bootstrap import did not parse")
		}
		populated, err := imported.WithRequiredModule()
		if err != nil || populated.Module != "KERNEL32" {
			t.Fatalf("WithRequiredModule(%s) = %#v, %v", function, populated, err)
		}
	}
	unsupported, _ := ParseImport("__imp_CustomAPI")
	if _, err := unsupported.WithRequiredModule(); err == nil || !strings.Contains(err.Error(), "not in MODULE$Function format") {
		t.Fatalf("bare custom import error = %v", err)
	}

	imported, _ := ParseImport("__imp_KERNEL32$LoadLibraryA")
	vectors := []struct {
		method       Method
		moduleHash   uint32
		functionHash uint32
	}{
		{MethodDJB2, 0x4ff6ec75, 0x5fbff0fb},
		{MethodFNV1A, 0xe26c18ed, 0x53b2070f},
		{MethodROR13, 0x6a4abc5b, 0xec0e4e8e},
		{MethodSDBM, 0xa7ac9f50, 0xdf2bbbec},
	}
	for _, vector := range vectors {
		resolver := Resolver{Function: "resolve", Method: vector.method}
		moduleHash, err := imported.ModuleHash(resolver)
		if err != nil {
			t.Fatal(err)
		}
		functionHash, err := imported.FunctionHash(resolver)
		if err != nil {
			t.Fatal(err)
		}
		if moduleHash != vector.moduleHash || functionHash != vector.functionHash {
			t.Errorf("%s hashes = %#08x/%#08x, want %#08x/%#08x", vector.method, moduleHash, functionHash, vector.moduleHash, vector.functionHash)
		}
	}
	if _, err := imported.ModuleHash(Resolver{Method: MethodStrings}); err == nil {
		t.Error("string resolver unexpectedly produced module hash")
	}
}

func TestBuildInvocationStringLayouts(t *testing.T) {
	t.Parallel()
	imported := Import{Module: "KERNEL32", Function: "Sleep", Valid: true}
	resolver := Resolver{Function: "resolve", Method: MethodStrings}

	x86, err := BuildInvocation(coff.MachineI386, imported, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := x86.ModuleString.PushOrder, []uint32{0, 0, 0x32334c45, 0x4e52454b}; !reflect.DeepEqual(got, want) {
		t.Fatalf("x86 module pushes = %#v, want %#v", got, want)
	}
	if got, want := x86.FunctionString.PushOrder, []uint32{0x70, 0x65656c53}; !reflect.DeepEqual(got, want) {
		t.Fatalf("x86 function pushes = %#v, want %#v", got, want)
	}
	if x86.CleanupSize != 32 {
		t.Fatalf("x86 cleanup = %d, want 32", x86.CleanupSize)
	}

	x64, err := BuildInvocation(coff.MachineAMD64, imported, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if x64.ModuleOffset != 0x20 || x64.FunctionOffset != 0x30 || x64.FrameSize != 0x40 || x64.DirtyFrameSize != 0x48 {
		t.Fatalf("x64 frame = module %#x function %#x size %#x dirty %#x", x64.ModuleOffset, x64.FunctionOffset, x64.FrameSize, x64.DirtyFrameSize)
	}
	if got, want := x64.ModuleString.Words, []uint64{0x32334c454e52454b, 0}; !reflect.DeepEqual(got, want) {
		t.Fatalf("x64 module words = %#v, want %#v", got, want)
	}
	if got, want := x64.FunctionString.Words, []uint64{0x0000007065656c53}; !reflect.DeepEqual(got, want) {
		t.Fatalf("x64 function words = %#v, want %#v", got, want)
	}

	hashInvocation, err := BuildInvocation(coff.MachineAMD64, imported, Resolver{Function: "resolve", Method: MethodROR13})
	if err != nil {
		t.Fatal(err)
	}
	if hashInvocation.ModuleHash != 0x6a4abc5b || hashInvocation.FunctionHash != 0xdb2d49b0 || hashInvocation.FrameSize != 0x20 || hashInvocation.DirtyFrameSize != 0x28 {
		t.Fatalf("hash invocation = %#v", hashInvocation)
	}
	if _, err := BuildInvocation(coff.MachineARM64, imported, resolver); err == nil {
		t.Error("ARM64 invocation unexpectedly succeeded")
	}
}

func TestInvocationReturnsDefensiveData(t *testing.T) {
	t.Parallel()
	invocation, err := BuildInvocation(coff.MachineAMD64, Import{Module: "K", Function: "F"}, Resolver{Function: "r", Method: MethodStrings})
	if err != nil {
		t.Fatal(err)
	}
	copyOfBytes := append([]byte(nil), invocation.ModuleString.Bytes...)
	invocation.FunctionString.Bytes[0] = 'X'
	if !reflect.DeepEqual(copyOfBytes, invocation.ModuleString.Bytes) {
		t.Fatal("independent string values unexpectedly share storage")
	}
}
