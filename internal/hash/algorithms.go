// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package hash

// DJB2 implements Dan Bernstein's djb2 hash.
type DJB2 struct{}

func (DJB2) Name() string { return "djb2" }

func (DJB2) Sum32(data []byte) uint32 {
	hash := uint32(5381)
	for _, value := range data {
		hash = hash*33 + uint32(value)
	}
	return hash
}

// FNV1A implements FNV-1a 32-bit.
type FNV1A struct{}

func (FNV1A) Name() string { return "fnv1a" }

func (FNV1A) Sum32(data []byte) uint32 {
	hash := uint32(0x811c9dc5)
	for _, value := range data {
		hash ^= uint32(value)
		hash *= 0x01000193
	}
	return hash
}

// ROR13 implements Crystal Palace's signed-byte ROR13 variant.
type ROR13 struct{}

func (ROR13) Name() string { return "ror13" }

func (ROR13) Sum32(data []byte) uint32 {
	var result int64
	for _, value := range data {
		result = javaRotateRight32(result, 13)
		// Java byte is signed; this differs from the more common ROR13
		// implementation for input bytes >= 0x80.
		result += int64(int8(value))
	}
	return uint32(result)
}

// javaRotateRight32 preserves ROR13.ROR's Java long shifts and final DWORD
// mask, including behavior when the prior signed-byte addition made value
// negative.
func javaRotateRight32(value int64, bits uint) int64 {
	a := int64(uint64(value) >> bits)
	b := value << (32 - bits)
	return (a | b) & 0xffffffff
}

// SDBM implements the sdbm hash with Java int wraparound.
type SDBM struct{}

func (SDBM) Name() string { return "sdbm" }

func (SDBM) Sum32(data []byte) uint32 {
	var hash uint32
	for _, value := range data {
		hash = uint32(value) + (hash << 6) + (hash << 16) - hash
	}
	return hash
}
