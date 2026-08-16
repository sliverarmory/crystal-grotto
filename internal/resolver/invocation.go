// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package resolver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/sliverarmory/crystal-grotto/internal/binutil"
	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

// StringData describes a zero-terminated resolver string in its padded stack
// representation. Words are in increasing memory order. PushOrder is populated
// for x86 and contains DWORD immediates in upstream emission order.
type StringData struct {
	Bytes     []byte
	Words     []uint64
	PushOrder []uint32
}

// Invocation contains all deterministic data needed to emit one resolver
// call. DirtyFrameSize captures upstream's extra eight-byte x64 alignment
// adjustment when the containing function has a dirty stack.
type Invocation struct {
	Method Method

	ModuleHash   uint32
	FunctionHash uint32

	ModuleString   StringData
	FunctionString StringData

	ModuleOffset   uint32
	FunctionOffset uint32
	FrameSize      uint32
	DirtyFrameSize uint32
	CleanupSize    uint32
}

// BuildInvocation calculates exact hash constants or padded string data for a
// resolver call without attempting instruction re-encoding.
func BuildInvocation(machine coff.Machine, imported Import, resolver Resolver) (Invocation, error) {
	if machine != coff.MachineI386 && machine != coff.MachineAMD64 {
		return Invocation{}, fmt.Errorf("resolver: unsupported machine %s", machine)
	}
	if resolver.Method.IsHash() {
		moduleHash, err := imported.ModuleHash(resolver)
		if err != nil {
			return Invocation{}, err
		}
		functionHash, err := imported.FunctionHash(resolver)
		if err != nil {
			return Invocation{}, err
		}
		result := Invocation{Method: resolver.Method, ModuleHash: moduleHash, FunctionHash: functionHash}
		if machine == coff.MachineI386 {
			result.CleanupSize = 8
		} else {
			result.FrameSize = 0x20
			result.DirtyFrameSize = 0x28
		}
		return result, nil
	}
	if !resolver.Method.IsStrings() {
		return Invocation{}, fmt.Errorf("Invalid resolve method: %s", resolver)
	}

	module, err := makeStringData(machine, imported.Module)
	if err != nil {
		return Invocation{}, fmt.Errorf("module string: %w", err)
	}
	function, err := makeStringData(machine, imported.Function)
	if err != nil {
		return Invocation{}, fmt.Errorf("function string: %w", err)
	}
	result := Invocation{Method: resolver.Method, ModuleString: module, FunctionString: function}
	if machine == coff.MachineI386 {
		total := uint64(len(module.Bytes)) + uint64(len(function.Bytes))
		if total > math.MaxUint32-8 {
			return Invocation{}, errors.New("resolver string stack exceeds 32 bits")
		}
		result.CleanupSize = uint32(total + 8)
		return result, nil
	}

	result.ModuleOffset = 0x20
	functionOffset := uint64(result.ModuleOffset) + uint64(len(module.Bytes))
	frameSize := functionOffset + uint64(len(function.Bytes))
	if remainder := frameSize % 16; remainder != 0 {
		frameSize += 16 - remainder
	}
	if functionOffset > math.MaxUint32 || frameSize > math.MaxUint32-8 {
		return Invocation{}, errors.New("resolver string frame exceeds 32 bits")
	}
	result.FunctionOffset = uint32(functionOffset)
	result.FrameSize = uint32(frameSize)
	result.DirtyFrameSize = uint32(frameSize + 8)
	return result, nil
}

func makeStringData(machine coff.Machine, value string) (StringData, error) {
	raw := binutil.UTF8Z(value)
	if len(raw) > math.MaxInt-7 {
		return StringData{}, errors.New("resolver string length overflows")
	}
	if remainder := len(raw) % 8; remainder != 0 {
		raw = append(raw, make([]byte, 8-remainder)...)
	}
	result := StringData{Bytes: append([]byte(nil), raw...)}
	for offset := 0; offset < len(raw); offset += 8 {
		result.Words = append(result.Words, binary.LittleEndian.Uint64(raw[offset:offset+8]))
	}
	if machine == coff.MachineI386 {
		for offset := len(raw); offset > 0; offset -= 4 {
			result.PushOrder = append(result.PushOrder, binary.LittleEndian.Uint32(raw[offset-4:offset]))
		}
	}
	return result, nil
}
