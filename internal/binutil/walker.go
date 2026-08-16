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
	"io"
	"strings"
)

// Walker is a bounded binary reader with nested absolute-position states.
// GoTo and Mark push a state; Return restores the previous state.
type Walker struct {
	data      []byte
	positions []int
	order     binary.ByteOrder
	sane      bool
	err       error
}

// NewWalker creates a little-endian walker at offset zero.
func NewWalker(data []byte) *Walker {
	return &Walker{
		data:      data,
		positions: []int{0},
		order:     binary.LittleEndian,
		sane:      true,
	}
}

// Little selects little-endian integer decoding.
func (w *Walker) Little() { w.order = binary.LittleEndian }

// Big selects big-endian integer decoding.
func (w *Walker) Big() { w.order = binary.BigEndian }

// IsSane reports whether every operation on this walker has succeeded.
func (w *Walker) IsSane() bool {
	// Make Walker's zero value safe even though NewWalker is the normal entry
	// point. A zero walker has not observed an error yet.
	return w.sane || (len(w.positions) == 0 && w.err == nil)
}

// Err returns the first walker error.
func (w *Walker) Err() error { return w.err }

// Position returns the absolute offset in the current state.
func (w *Walker) Position() int {
	if len(w.positions) == 0 {
		return 0
	}
	return w.positions[len(w.positions)-1]
}

// Remaining returns the unread byte count in the current state.
func (w *Walker) Remaining() int { return len(w.data) - w.Position() }

// Complete reports whether the current state is at EOF.
func (w *Walker) Complete() bool { return w.Remaining() == 0 }

func (w *Walker) fail(err error) error {
	w.sane = false
	if w.err == nil {
		w.err = err
	}
	return err
}

// ReadBytes reads exactly length bytes and returns a detached copy.
func (w *Walker) ReadBytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, w.fail(fmt.Errorf("invalid negative byte count %d", length))
	}
	if length > w.Remaining() {
		return nil, w.fail(fmt.Errorf("%w: need %d bytes at offset %d, have %d", io.ErrUnexpectedEOF, length, w.Position(), w.Remaining()))
	}
	start := w.Position()
	w.positions[len(w.positions)-1] += length
	result := make([]byte, length)
	copy(result, w.data[start:start+length])
	return result, nil
}

// ReadByte reads one unsigned byte.
func (w *Walker) ReadByte() (byte, error) {
	data, err := w.ReadBytes(1)
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

// Skip advances by length bytes.
func (w *Walker) Skip(length int) error {
	if length < 0 || length > w.Remaining() {
		return w.fail(fmt.Errorf("%w: skip %d bytes at offset %d in %d-byte buffer", ErrBounds, length, w.Position(), len(w.data)))
	}
	w.positions[len(w.positions)-1] += length
	return nil
}

// Mark pushes a nested state at the current absolute position.
func (w *Walker) Mark() { w.positions = append(w.positions, w.Position()) }

// GoTo pushes a nested state at an absolute offset.
func (w *Walker) GoTo(offset int) error {
	if offset < 0 || offset > len(w.data) {
		return w.fail(fmt.Errorf("%w: offset %d in %d-byte buffer", ErrBounds, offset, len(w.data)))
	}
	w.positions = append(w.positions, offset)
	return nil
}

// Return pops a nested state and restores the prior position.
func (w *Walker) Return() error {
	if len(w.positions) <= 1 {
		return w.fail(fmt.Errorf("walker state underflow"))
	}
	w.positions = w.positions[:len(w.positions)-1]
	return nil
}

// ReadUint16 reads an unsigned 16-bit integer.
func (w *Walker) ReadUint16() (uint16, error) {
	data, err := w.ReadBytes(2)
	if err != nil {
		return 0, err
	}
	return w.order.Uint16(data), nil
}

// ReadInt32 reads a signed 32-bit integer.
func (w *Walker) ReadInt32() (int32, error) {
	value, err := w.ReadUint32()
	return int32(value), err
}

// ReadUint32 reads an unsigned 32-bit integer.
func (w *Walker) ReadUint32() (uint32, error) {
	data, err := w.ReadBytes(4)
	if err != nil {
		return 0, err
	}
	return w.order.Uint32(data), nil
}

// ReadInt64 reads a signed 64-bit integer.
func (w *Walker) ReadInt64() (int64, error) {
	value, err := w.ReadUint64()
	return int64(value), err
}

// ReadUint64 reads an unsigned 64-bit integer.
func (w *Walker) ReadUint64() (uint64, error) {
	data, err := w.ReadBytes(8)
	if err != nil {
		return 0, err
	}
	return w.order.Uint64(data), nil
}

// ReadStringA reads length bytes, truncates at the first NUL, and decodes them
// as UTF-8. Invalid UTF-8 is replaced instead of being exposed to callers.
func (w *Walker) ReadStringA(length int) (string, error) {
	data, err := w.ReadBytes(length)
	if err != nil {
		return "", err
	}
	if index := bytes.IndexByte(data, 0); index >= 0 {
		data = data[:index]
	}
	return strings.ToValidUTF8(string(data), "\uFFFD"), nil
}

// ReadCString reads up to a NUL byte. For upstream compatibility, the NUL
// terminator remains unread; callers may Skip(1) when they want to consume it.
func (w *Walker) ReadCString() (string, error) {
	remainder := w.data[w.Position():]
	length := bytes.IndexByte(remainder, 0)
	if length < 0 {
		return "", w.fail(fmt.Errorf("%w: unterminated string at offset %d", io.ErrUnexpectedEOF, w.Position()))
	}
	return w.ReadStringA(length)
}
