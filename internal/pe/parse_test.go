// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package pe

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestParsePE32AndPE32PlusImports(t *testing.T) {
	for _, test := range []struct {
		name    string
		is64    bool
		machine coff.Machine
	}{
		{name: "PE32", machine: coff.MachineI386},
		{name: "PE32+", is64: true, machine: coff.MachineAMD64},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := buildPEFixture(test.is64)
			machine, err := ParseMachine(fixture)
			if err != nil || machine != test.machine {
				t.Fatalf("ParseMachine() = %v, %v; want %v", machine, err, test.machine)
			}
			object, err := Parse(fixture)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if object.Machine != test.machine || object.OptionalHeader.Is64() != test.is64 {
				t.Fatalf("object machine/header = %v/%t", object.Machine, object.OptionalHeader.Is64())
			}
			if object.EntryPoint() != 0x1010 || object.OptionalHeader.SizeOfImage != 0x2000 {
				t.Fatalf("optional header = %#v", object.OptionalHeader)
			}
			if len(object.Sections) != 1 || object.Sections[0].Name != ".idata" || len(object.Sections[0].Data) != 0x400 {
				t.Fatalf("sections = %#v", object.Sections)
			}
			if len(object.Descriptors) != 1 || object.Descriptors[0].Name != "KERNEL32.dll" {
				t.Fatalf("descriptors = %#v", object.Descriptors)
			}
			if len(object.Imports) != 2 {
				t.Fatalf("imports = %#v", object.Imports)
			}
			named := object.Imports[0]
			if named.Module != "KERNEL32.dll" || named.Function != "Sleep" || named.Hint != 0x33 || named.ByOrdinal {
				t.Fatalf("named import = %#v", named)
			}
			ordinal := object.Imports[1]
			if !ordinal.ByOrdinal || ordinal.Ordinal != 7 || ordinal.Function != "" {
				t.Fatalf("ordinal import = %#v", ordinal)
			}
			wantSecondAddress := uint32(0x1124)
			if test.is64 {
				wantSecondAddress = 0x1128
			}
			if named.Address != 0x1120 || ordinal.Address != wantSecondAddress {
				t.Fatalf("IAT addresses = %#x, %#x", named.Address, ordinal.Address)
			}
			first := object.String()
			if first != object.String() || !strings.Contains(first, "KERNEL32.dll$Sleep") {
				t.Fatalf("unexpected/non-deterministic String():\n%s", first)
			}
		})
	}
}

func TestParseDoesNotAllocateSizeOfImage(t *testing.T) {
	fixture := buildPEFixture(true)
	optionalOffset := 0x80 + 4 + 20
	binary.LittleEndian.PutUint32(fixture[optionalOffset+56:optionalOffset+60], ^uint32(0))
	object, err := Parse(fixture)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if object.OptionalHeader.SizeOfImage != ^uint32(0) {
		t.Fatalf("SizeOfImage = %#x", object.OptionalHeader.SizeOfImage)
	}
}

func TestParseRejectsMalformedPE(t *testing.T) {
	valid := buildPEFixture(false)
	optionalOffset := 0x80 + 4 + 20
	sectionOffset := optionalOffset + 224
	tests := []struct {
		name string
		data func() []byte
	}{
		{name: "empty", data: func() []byte { return nil }},
		{name: "not MZ", data: func() []byte {
			value := append([]byte(nil), valid...)
			value[0] = 0
			return value
		}},
		{name: "e_lfanew outside file", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(value[0x3c:0x40], uint32(len(value)))
			return value
		}},
		{name: "bad signature", data: func() []byte {
			value := append([]byte(nil), valid...)
			value[0x80] = 'N'
			return value
		}},
		{name: "unknown machine", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint16(value[0x84:0x86], 0xffff)
			return value
		}},
		{name: "invalid optional magic", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint16(value[optionalOffset:optionalOffset+2], 0xffff)
			return value
		}},
		{name: "too many data directories", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(value[optionalOffset+92:optionalOffset+96], 17)
			return value
		}},
		{name: "section raw data outside file", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(value[sectionOffset+20:sectionOffset+24], uint32(len(value)))
			return value
		}},
		{name: "module name RVA outside image", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(value[0x200+12:0x200+16], 0x90000000)
			return value
		}},
		{name: "thunk name RVA outside image", data: func() []byte {
			value := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(value[0x320:0x324], 0x70000000)
			return value
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(test.data()); err == nil {
				t.Fatal("Parse() unexpectedly succeeded")
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add(buildPEFixture(false))
	f.Add(buildPEFixture(true))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data)
		_, _ = ParseMachine(data)
	})
}

func buildPEFixture(is64 bool) []byte {
	const (
		peOffset   = 0x80
		rawPointer = 0x200
		sectionRVA = 0x1000
	)
	optionalSize := 224
	machine := coff.MachineI386
	if is64 {
		optionalSize = 240
		machine = coff.MachineAMD64
	}
	fixture := make([]byte, 0x600)
	binary.LittleEndian.PutUint16(fixture[:2], 0x5a4d)
	binary.LittleEndian.PutUint32(fixture[0x3c:0x40], peOffset)
	binary.LittleEndian.PutUint32(fixture[peOffset:peOffset+4], 0x00004550)
	coffOffset := peOffset + 4
	binary.LittleEndian.PutUint16(fixture[coffOffset:coffOffset+2], uint16(machine))
	binary.LittleEndian.PutUint16(fixture[coffOffset+2:coffOffset+4], 1)
	binary.LittleEndian.PutUint16(fixture[coffOffset+16:coffOffset+18], uint16(optionalSize))
	binary.LittleEndian.PutUint16(fixture[coffOffset+18:coffOffset+20], 0x2022)

	optionalOffset := coffOffset + 20
	optional := fixture[optionalOffset : optionalOffset+optionalSize]
	directoryOffset := 96
	if is64 {
		binary.LittleEndian.PutUint16(optional[:2], OptionalMagicPE32Plus)
		binary.LittleEndian.PutUint64(optional[24:32], 0x140000000)
		binary.LittleEndian.PutUint32(optional[108:112], 16)
		directoryOffset = 112
	} else {
		binary.LittleEndian.PutUint16(optional[:2], OptionalMagicPE32)
		binary.LittleEndian.PutUint32(optional[28:32], 0x400000)
		binary.LittleEndian.PutUint32(optional[92:96], 16)
	}
	binary.LittleEndian.PutUint32(optional[16:20], 0x1010)
	binary.LittleEndian.PutUint32(optional[32:36], 0x1000)
	binary.LittleEndian.PutUint32(optional[36:40], 0x200)
	binary.LittleEndian.PutUint32(optional[56:60], 0x2000)
	binary.LittleEndian.PutUint32(optional[60:64], 0x200)
	importDirectory := directoryOffset + DirectoryImport*8
	binary.LittleEndian.PutUint32(optional[importDirectory:importDirectory+4], sectionRVA)
	binary.LittleEndian.PutUint32(optional[importDirectory+4:importDirectory+8], 40)

	sectionOffset := optionalOffset + optionalSize
	section := fixture[sectionOffset : sectionOffset+40]
	copy(section[:8], ".idata")
	binary.LittleEndian.PutUint32(section[8:12], 0x400)
	binary.LittleEndian.PutUint32(section[12:16], sectionRVA)
	binary.LittleEndian.PutUint32(section[16:20], 0x400)
	binary.LittleEndian.PutUint32(section[20:24], rawPointer)
	binary.LittleEndian.PutUint32(section[36:40], coff.SectionInitializedData|coff.SectionMemRead|coff.SectionMemWrite)

	// Import descriptor followed by an all-zero terminator.
	descriptor := fixture[rawPointer : rawPointer+20]
	binary.LittleEndian.PutUint32(descriptor[:4], 0x1160) // deliberately unused by Crystal Palace
	binary.LittleEndian.PutUint32(descriptor[12:16], 0x1100)
	binary.LittleEndian.PutUint32(descriptor[16:20], 0x1120)
	copy(fixture[0x300:], "KERNEL32.dll\x00")
	if is64 {
		binary.LittleEndian.PutUint64(fixture[0x320:0x328], 0x1140)
		binary.LittleEndian.PutUint64(fixture[0x328:0x330], uint64(1)<<63|7)
	} else {
		binary.LittleEndian.PutUint32(fixture[0x320:0x324], 0x1140)
		binary.LittleEndian.PutUint32(fixture[0x324:0x328], uint32(1)<<31|7)
	}
	binary.LittleEndian.PutUint16(fixture[0x340:0x342], 0x33)
	copy(fixture[0x342:], "Sleep\x00")
	return fixture
}
