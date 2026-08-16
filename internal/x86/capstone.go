// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.
// See LICENSE.upstream.

package x86

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sync"

	gocapstone "github.com/moloch--/go-capstone"
)

const maximumInstructionLength = 15

// Capstone is a portable x86 disassembler backed by an embedded WebAssembly
// build of Capstone. Calls are serialized because one Capstone handle and its
// WebAssembly memory are owned by the instance.
type Capstone struct {
	mu     sync.Mutex
	engine *gocapstone.Engine
	mode   Mode
}

var _ Disassembler = (*Capstone)(nil)

// NewCapstone opens a decoder for 32-bit or 64-bit x86 instructions. Intel
// syntax is selected because it is the closest available match to Crystal
// Palace's customized Iced MASM formatter. Exact formatter parity is not
// implied; Operands remains authoritative Capstone output.
func NewCapstone(ctx context.Context, mode Mode) (*Capstone, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	capstoneMode, err := mode.capstoneMode()
	if err != nil {
		return nil, err
	}
	engine, err := gocapstone.Open(
		ctx,
		gocapstone.ArchX86,
		capstoneMode,
		gocapstone.WithSyntax(gocapstone.SyntaxIntel),
	)
	if err != nil {
		return nil, fmt.Errorf("x86: open Capstone %s decoder: %w", mode, err)
	}
	return &Capstone{engine: engine, mode: mode}, nil
}

func (m Mode) capstoneMode() (gocapstone.Mode, error) {
	switch m {
	case Mode32:
		return gocapstone.Mode32, nil
	case Mode64:
		return gocapstone.Mode64, nil
	default:
		return 0, fmt.Errorf("%w: %d", ErrInvalidMode, m)
	}
}

// Mode returns the decoder's immutable execution mode.
func (c *Capstone) Mode() Mode {
	if c == nil {
		return 0
	}
	return c.mode
}

// Disassemble decodes the entire input. Unlike cs_disasm's default behavior,
// it rejects a valid prefix followed by an invalid or truncated instruction.
// Empty input succeeds with an empty, non-nil instruction slice.
func (c *Capstone) Disassemble(ctx context.Context, code []byte, address uint64) ([]Instruction, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("x86: disassemble: %w", err)
	}
	if uint64(len(code)) > math.MaxUint32 {
		return nil, ErrInputTooLarge
	}
	if len(code) > 0 && uint64(len(code)-1) > math.MaxUint64-address {
		return nil, ErrAddressOverflow
	}
	if c == nil {
		return nil, ErrClosed
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.engine == nil {
		return nil, ErrClosed
	}
	if len(code) == 0 {
		return make([]Instruction, 0), nil
	}

	decoded, err := c.engine.Disassemble(ctx, code, address)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, fmt.Errorf("x86: disassemble: %w", contextErr)
		}
		return nil, newDecodeError(code, address, 0, fmt.Errorf("%w: %v", ErrInvalidInstruction, err))
	}

	instructions := make([]Instruction, 0, len(decoded))
	offset := 0
	for _, raw := range decoded {
		expectedAddress := address + uint64(offset)
		if raw.Address != expectedAddress {
			return nil, newDecodeError(code, address, offset, fmt.Errorf("%w: address is %#x, want %#x", ErrBackendInvariant, raw.Address, expectedAddress))
		}
		size := int(raw.Size)
		if size < 1 || size > maximumInstructionLength || len(raw.Bytes) != size {
			return nil, newDecodeError(code, address, offset, fmt.Errorf("%w: size is %d with %d raw bytes", ErrBackendInvariant, size, len(raw.Bytes)))
		}
		if size > len(code)-offset {
			return nil, newDecodeError(code, address, offset, fmt.Errorf("%w: instruction size %d exceeds remaining input", ErrBackendInvariant, size))
		}
		if !bytes.Equal(raw.Bytes, code[offset:offset+size]) {
			return nil, newDecodeError(code, address, offset, fmt.Errorf("%w: raw bytes differ from input", ErrBackendInvariant))
		}
		if raw.Illegal {
			return nil, newDecodeError(code, address, offset, ErrInvalidInstruction)
		}
		if raw.Mnemonic == "" {
			return nil, newDecodeError(code, address, offset, fmt.Errorf("%w: empty mnemonic", ErrBackendInvariant))
		}

		instructions = append(instructions, Instruction{
			Address:  raw.Address,
			Bytes:    append([]byte(nil), raw.Bytes...),
			Mnemonic: raw.Mnemonic,
			Operands: raw.OpStr,
			// go-capstone v0.0.1 does not expose architecture-specific
			// cs_detail or a canonical Iced-equivalent opcode form.
			Form: "",
			Detail: &Detail{
				InstructionID:   raw.ID,
				AliasID:         raw.AliasID,
				IsAlias:         raw.IsAlias,
				UsesAliasDetail: raw.UsesAliasDetails,
			},
		})
		offset += size
	}

	if offset != len(code) {
		return nil, newDecodeError(code, address, offset, ErrInvalidInstruction)
	}
	return instructions, nil
}

func newDecodeError(code []byte, address uint64, offset int, err error) *DecodeError {
	if offset < 0 {
		offset = 0
	}
	if offset > len(code) {
		offset = len(code)
	}
	errorAddress := address
	if uint64(offset) <= math.MaxUint64-address {
		errorAddress += uint64(offset)
	} else {
		errorAddress = math.MaxUint64
	}
	return &DecodeError{
		Offset:    offset,
		Address:   errorAddress,
		Remaining: append([]byte(nil), code[offset:]...),
		Err:       err,
	}
}

// Close releases the Capstone handle and WebAssembly runtime. It is safe to
// call concurrently with Disassemble and safe to call more than once.
func (c *Capstone) Close(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.engine == nil {
		return nil
	}
	engine := c.engine
	c.engine = nil
	if err := engine.Close(ctx); err != nil {
		return fmt.Errorf("x86: close Capstone %s decoder: %w", c.mode, err)
	}
	return nil
}

// IsClosed reports whether Close has released the backend. It is intended for
// lifecycle diagnostics; callers must still handle ErrClosed because another
// goroutine can close the decoder immediately after this call.
func (c *Capstone) IsClosed() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.engine == nil
}

// IsDecodeError reports whether err describes a malformed instruction stream.
func IsDecodeError(err error) bool {
	var decodeErr *DecodeError
	return errors.As(err, &decodeErr)
}
