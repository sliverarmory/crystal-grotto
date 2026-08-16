// SPDX-License-Identifier: GPL-3.0-only

package hash

import (
	"reflect"
	"testing"
)

func TestAlgorithmsKnownVectors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
		want uint32
	}{
		{name: "djb2", data: nil, want: 0x00001505},
		{name: "djb2", data: []byte("hello"), want: 0x0f923099},
		{name: "fnv1a", data: nil, want: 0x811c9dc5},
		{name: "fnv1a", data: []byte("hello"), want: 0x4f9f2cab},
		{name: "ror13", data: nil, want: 0},
		{name: "ror13", data: []byte("LoadLibraryA"), want: 0xec0e4e8e},
		{name: "ror13", data: []byte{0x80}, want: 0xffffff80},
		{name: "ror13", data: []byte{0xff, 1}, want: 0},
		{name: "sdbm", data: nil, want: 0},
		{name: "sdbm", data: []byte("hello"), want: 0x28d19932},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := Apply(test.name, test.data)
			if err != nil || got != test.want {
				t.Fatalf("Apply(%q, %x) = %#08x, %v; want %#08x", test.name, test.data, got, err, test.want)
			}
		})
	}
}

func TestRegistry(t *testing.T) {
	t.Parallel()
	want := []string{"djb2", "fnv1a", "ror13", "sdbm"}
	if got := Names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Names = %#v, want %#v", got, want)
	}
	if got := NamesString(); got != "djb2, fnv1a, ror13, sdbm" {
		t.Fatalf("NamesString = %q", got)
	}
	for _, name := range want {
		if !IsName(name) {
			t.Errorf("IsName(%q) = false", name)
		}
	}
	for _, name := range []string{"DJB2", "ror", ""} {
		if IsName(name) {
			t.Errorf("IsName(%q) = true", name)
		}
	}
	if _, err := Apply("unknown", nil); err == nil {
		t.Error("unknown algorithm unexpectedly succeeded")
	}
	copyOfNames := Names()
	copyOfNames[0] = "changed"
	if Names()[0] != "djb2" {
		t.Error("Names exposed registry storage")
	}
}

func TestPrefixes(t *testing.T) {
	t.Parallel()
	for _, symbol := range []string{"__djb2_Value", "___fnv1a_Value", "__ror13_", "___sdbm_X"} {
		if !MatchesPrefix(symbol) {
			t.Errorf("MatchesPrefix(%q) = false", symbol)
		}
		algorithm, err := GetFromPrefix(symbol)
		if err != nil {
			t.Errorf("GetFromPrefix(%q): %v", symbol, err)
			continue
		}
		prefix, _ := Prefix(symbol)
		if prefix != "__"+algorithm.Name()+"_" && prefix != "___"+algorithm.Name()+"_" {
			t.Errorf("Prefix(%q) = %q for %s", symbol, prefix, algorithm.Name())
		}
	}

	value, err := RemovePrefix("___ror13_LoadLibraryA")
	if err != nil || value != "LoadLibraryA" {
		t.Fatalf("RemovePrefix = %q, %v", value, err)
	}
	got, err := ApplyIntrinsic("___ror13_LoadLibraryA")
	if err != nil || got != 0xec0e4e8e {
		t.Fatalf("ApplyIntrinsic = %#x, %v", got, err)
	}
	for _, symbol := range []string{"__ROR13_Value", "_ror13_Value", "ror13_Value", ""} {
		if MatchesPrefix(symbol) {
			t.Errorf("MatchesPrefix(%q) = true", symbol)
		}
		if _, err := RemovePrefix(symbol); err == nil {
			t.Errorf("RemovePrefix(%q) unexpectedly succeeded", symbol)
		}
	}
}

func TestModuleAndFunctionCasing(t *testing.T) {
	t.Parallel()
	upper, err := ApplyModule("ror13", "KERNEL32")
	if err != nil || upper != 0x6a4abc5b {
		t.Fatalf("ApplyModule uppercase = %#x, %v", upper, err)
	}
	lower, err := ApplyModule("ror13", "kernel32")
	if err != nil || lower != upper {
		t.Fatalf("ApplyModule lowercase = %#x, %v; uppercase %#x", lower, err, upper)
	}
	function, err := ApplyFunction("ror13", "LoadLibraryA")
	if err != nil || function != 0xec0e4e8e {
		t.Fatalf("ApplyFunction = %#x, %v", function, err)
	}
	lowerFunction, err := ApplyFunction("ror13", "loadlibrarya")
	if err != nil || lowerFunction == function {
		t.Fatalf("function casing was not preserved: %#x, %v", lowerFunction, err)
	}
	if _, err := ApplyModule("ror13", ""); err != nil {
		t.Errorf("empty module should hash upstream's .DLL normalization: %v", err)
	}
}

func FuzzAlgorithms(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{0xff, 0x80, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, name := range Names() {
			if _, err := Apply(name, data); err != nil {
				t.Fatalf("Apply(%q): %v", name, err)
			}
		}
	})
}

func FuzzPrefixes(f *testing.F) {
	for _, seed := range []string{"__ror13_X", "___djb2_", "__ROR13_X", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, symbol string) {
		matched := MatchesPrefix(symbol)
		_, removeErr := RemovePrefix(symbol)
		_, getErr := GetFromPrefix(symbol)
		if matched != (removeErr == nil) || matched != (getErr == nil) {
			t.Fatalf("inconsistent prefix APIs for %q", symbol)
		}
	})
}
