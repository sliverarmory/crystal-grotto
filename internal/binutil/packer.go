// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package binutil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

// Packer incrementally writes primitive values. Like java.nio.ByteBuffer, its
// default byte order is big endian; Crystal Palace callers normally select
// Little explicitly.
type Packer struct {
	buffer bytes.Buffer
	order  binary.ByteOrder
}

func (p *Packer) byteOrder() binary.ByteOrder {
	if p.order == nil {
		return binary.BigEndian
	}
	return p.order
}

// NewPacker creates an empty, big-endian packer.
func NewPacker() *Packer {
	return &Packer{order: binary.BigEndian}
}

// Little selects little-endian integer encoding and returns p for chaining.
func (p *Packer) Little() *Packer {
	p.order = binary.LittleEndian
	return p
}

// Big selects big-endian integer encoding and returns p for chaining.
func (p *Packer) Big() *Packer {
	p.order = binary.BigEndian
	return p
}

// Pad writes count NUL bytes.
func (p *Packer) Pad(count int) error {
	if count < 0 {
		return fmt.Errorf("padding must not be negative: %d", count)
	}
	p.buffer.Write(make([]byte, count))
	return nil
}

// AddByte writes the low eight bits of value.
func (p *Packer) AddByte(value int64) { p.buffer.WriteByte(byte(value)) }

// AddBytes appends data.
func (p *Packer) AddBytes(data []byte) { _, _ = p.buffer.Write(data) }

// AddShort writes the low 16 bits of value.
func (p *Packer) AddShort(value int64) {
	var data [2]byte
	p.byteOrder().PutUint16(data[:], uint16(value))
	p.AddBytes(data[:])
}

// AddUShort is the upstream addUShort equivalent.
func (p *Packer) AddUShort(value uint64) { p.AddShort(int64(value)) }

// AddInt writes the low 32 bits of value.
func (p *Packer) AddInt(value int64) {
	var data [4]byte
	p.byteOrder().PutUint32(data[:], uint32(value))
	p.AddBytes(data[:])
}

// AddLong writes all 64 bits of value.
func (p *Packer) AddLong(value int64) {
	var data [8]byte
	p.byteOrder().PutUint64(data[:], uint64(value))
	p.AddBytes(data[:])
}

// AddData prefixes data with its 32-bit length and appends it.
func (p *Packer) AddData(data []byte) error {
	if uint64(len(data)) > math.MaxUint32 {
		return fmt.Errorf("data length %d does not fit in a DWORD", len(data))
	}
	p.AddInt(int64(len(data)))
	p.AddBytes(data)
	return nil
}

// AddDataVerify prefixes data with its Adler-32 checksum and appends it.
func (p *Packer) AddDataVerify(data []byte) {
	p.AddInt(int64(Adler32(data)))
	p.AddBytes(data)
}

// AddWideString writes a length-prefixed, NUL-terminated UTF-16LE string.
func (p *Packer) AddWideString(text string) error {
	return p.AddData(UTF16LEZ(text))
}

// AddUTF8String writes a length-prefixed, NUL-terminated UTF-8 string.
func (p *Packer) AddUTF8String(text string) error {
	return p.AddData(UTF8Z(text))
}

// Len returns the packed byte count.
func (p *Packer) Len() int { return p.buffer.Len() }

// Bytes returns a detached copy of the packed bytes.
func (p *Packer) Bytes() []byte {
	return bytes.Clone(p.buffer.Bytes())
}
