// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.

package spec

import (
	"encoding/binary"
	"fmt"
)

const (
	machineX86 = 0x014c
	machineX64 = 0x8664
)

// Capability describes the input program made available to a spec.
type Capability struct {
	Key      string
	Contents []byte
	Label    string
	Arch     string
}

// None constructs a build-only capability for an architecture or named label.
func None(archOrLabel string) (Capability, error) {
	arch := ""
	switch {
	case archOrLabel == "x86" || archOrLabel == "x64":
		arch = archOrLabel
	case len(archOrLabel) > 4 && archOrLabel[len(archOrLabel)-4:] == ".x86":
		arch = "x86"
	case len(archOrLabel) > 4 && archOrLabel[len(archOrLabel)-4:] == ".x64":
		arch = "x64"
	default:
		return Capability{}, fmt.Errorf("Label %s must end with .x86/.x64 or be x86/x64", archOrLabel)
	}
	return Capability{Contents: []byte{}, Label: archOrLabel, Arch: arch}, nil
}

// ParseCapability detects and minimally validates a Windows DLL or COFF object.
func ParseCapability(data []byte) (Capability, error) {
	if len(data) < 2 {
		return Capability{}, fmt.Errorf("Argument is not a COFF or DLL.")
	}
	magic := binary.LittleEndian.Uint16(data[:2])
	switch magic {
	case 0x5a4d:
		return ParseDLL(data)
	case machineX86, machineX64:
		return ParseObject(data)
	default:
		return Capability{}, fmt.Errorf("Argument is not a COFF or DLL.")
	}
}

// ParseObject constructs a capability from a COFF object header.
func ParseObject(data []byte) (Capability, error) {
	if len(data) < 20 {
		return Capability{}, fmt.Errorf("Invalid Object: COFF header is truncated")
	}
	arch, err := machineArch(binary.LittleEndian.Uint16(data[:2]))
	if err != nil {
		return Capability{}, fmt.Errorf("Invalid Object: %w", err)
	}
	return Capability{
		Key:      "$OBJECT",
		Contents: append([]byte(nil), data...),
		Label:    arch + ".o",
		Arch:     arch,
	}, nil
}

// ParseDLL constructs a capability from DOS and PE headers.
func ParseDLL(data []byte) (Capability, error) {
	if len(data) < 0x40 || binary.LittleEndian.Uint16(data[:2]) != 0x5a4d {
		return Capability{}, fmt.Errorf("Invalid DLL: File header is not 'MZ'")
	}
	peOffset := uint64(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if peOffset > uint64(len(data)) || uint64(len(data))-peOffset < 6 {
		return Capability{}, fmt.Errorf("Invalid DLL: PE header is truncated")
	}
	off := int(peOffset)
	if string(data[off:off+4]) != "PE\x00\x00" {
		return Capability{}, fmt.Errorf("Invalid DLL: PE signature is not 'PE'\\x00\\x00")
	}
	arch, err := machineArch(binary.LittleEndian.Uint16(data[off+4 : off+6]))
	if err != nil {
		return Capability{}, fmt.Errorf("Invalid DLL: %w", err)
	}
	return Capability{
		Key:      "$DLL",
		Contents: append([]byte(nil), data...),
		Label:    arch + ".dll",
		Arch:     arch,
	}, nil
}

// HasCapability reports whether the capability wraps a DLL or object.
func (c Capability) HasCapability() bool { return c.Key != "" }

// IsObject reports whether the capability wraps a COFF object.
func (c Capability) IsObject() bool { return c.Key == "$OBJECT" }

// IsDLL reports whether the capability wraps a DLL.
func (c Capability) IsDLL() bool { return c.Key == "$DLL" }

func machineArch(machine uint16) (string, error) {
	switch machine {
	case machineX86:
		return "x86", nil
	case machineX64:
		return "x64", nil
	default:
		return "", fmt.Errorf("unknown machine 0x%04x", machine)
	}
}
