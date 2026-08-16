// SPDX-License-Identifier: GPL-3.0-only

package binutil

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestWalkerEndianReads(t *testing.T) {
	t.Parallel()
	little := NewWalker([]byte{
		0x34, 0x12,
		0xef, 0xcd, 0xab, 0x89,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	})
	if got, err := little.ReadUint16(); err != nil || got != 0x1234 {
		t.Fatalf("ReadUint16 = %#x, %v", got, err)
	}
	if got, err := little.ReadInt32(); err != nil || got != int32(-1985229329) {
		t.Fatalf("ReadInt32 = %#x, %v", got, err)
	}
	if got, err := little.ReadInt64(); err != nil || got != 0x0102030405060708 {
		t.Fatalf("ReadInt64 = %#x, %v", got, err)
	}
	if !little.Complete() || !little.IsSane() {
		t.Fatalf("walker state: complete=%v sane=%v err=%v", little.Complete(), little.IsSane(), little.Err())
	}

	big := NewWalker([]byte{0x12, 0x34, 0x01, 0x02, 0x03, 0x04})
	big.Big()
	if got, err := big.ReadUint16(); err != nil || got != 0x1234 {
		t.Fatalf("big ReadUint16 = %#x, %v", got, err)
	}
	if got, err := big.ReadUint32(); err != nil || got != 0x01020304 {
		t.Fatalf("big ReadUint32 = %#x, %v", got, err)
	}
}

func TestWalkerNestedStates(t *testing.T) {
	t.Parallel()
	walker := NewWalker([]byte{0, 1, 2, 3, 4})
	if err := walker.Skip(1); err != nil {
		t.Fatal(err)
	}
	walker.Mark()
	if got, err := walker.ReadByte(); err != nil || got != 1 {
		t.Fatalf("marked ReadByte = %d, %v", got, err)
	}
	if err := walker.Return(); err != nil || walker.Position() != 1 {
		t.Fatalf("Return = %v, position %d", err, walker.Position())
	}
	if err := walker.GoTo(4); err != nil {
		t.Fatal(err)
	}
	if got, err := walker.ReadByte(); err != nil || got != 4 {
		t.Fatalf("GoTo ReadByte = %d, %v", got, err)
	}
	if err := walker.Return(); err != nil || walker.Position() != 1 {
		t.Fatalf("GoTo Return = %v, position %d", err, walker.Position())
	}
}

func TestWalkerStrings(t *testing.T) {
	t.Parallel()
	walker := NewWalker([]byte{'a', 'b', 0, 'x', 'y', 0})
	got, err := walker.ReadStringA(4)
	if err != nil || got != "ab" || walker.Position() != 4 {
		t.Fatalf("ReadStringA = %q, %v, position %d", got, err, walker.Position())
	}
	got, err = walker.ReadCString()
	if err != nil || got != "y" || walker.Position() != 5 {
		t.Fatalf("ReadCString = %q, %v, position %d", got, err, walker.Position())
	}
	if err := walker.Skip(1); err != nil || !walker.Complete() {
		t.Fatalf("consume terminator = %v, complete=%v", err, walker.Complete())
	}

	unterminated := NewWalker([]byte("abc"))
	if _, err := unterminated.ReadCString(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("unterminated error = %v", err)
	}
}

func TestWalkerBoundsAreSafe(t *testing.T) {
	t.Parallel()
	walker := NewWalker([]byte{1, 2})
	if _, err := walker.ReadBytes(3); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadBytes error = %v", err)
	}
	if walker.Position() != 0 || walker.IsSane() || walker.Err() == nil {
		t.Fatalf("walker after failed read: pos=%d sane=%v err=%v", walker.Position(), walker.IsSane(), walker.Err())
	}
	if err := walker.GoTo(-1); !errors.Is(err, ErrBounds) {
		t.Fatalf("GoTo(-1) error = %v", err)
	}
	if err := walker.Skip(-1); !errors.Is(err, ErrBounds) {
		t.Fatalf("Skip(-1) error = %v", err)
	}
	if err := NewWalker(nil).Return(); err == nil {
		t.Fatal("Return underflow unexpectedly succeeded")
	}
	var zero Walker
	if zero.Position() != 0 || zero.Remaining() != 0 || !zero.Complete() || !zero.IsSane() {
		t.Fatalf("zero walker is not safely readable: pos=%d remaining=%d complete=%v sane=%v", zero.Position(), zero.Remaining(), zero.Complete(), zero.IsSane())
	}
	if _, err := zero.ReadByte(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("zero walker ReadByte error = %v", err)
	}
}

func TestWalkerReadBytesReturnsCopy(t *testing.T) {
	t.Parallel()
	input := []byte{1, 2, 3}
	got, err := NewWalker(input).ReadBytes(3)
	if err != nil {
		t.Fatal(err)
	}
	got[0] = 9
	if bytes.Equal(got, input) || input[0] != 1 {
		t.Fatalf("read slice aliases input: got=%v input=%v", got, input)
	}
}

func FuzzWalker(f *testing.F) {
	f.Add([]byte{1, 2, 3, 0}, int16(2), int16(0))
	f.Add([]byte{}, int16(-1), int16(-1))
	f.Fuzz(func(t *testing.T, data []byte, countValue, offsetValue int16) {
		walker := NewWalker(data)
		count := int(countValue)
		offset := int(offsetValue)
		_, _ = walker.ReadBytes(count)
		if walker.Position() < 0 || walker.Position() > len(data) {
			t.Fatalf("position %d outside 0..%d", walker.Position(), len(data))
		}
		_ = walker.GoTo(offset)
		if walker.Position() < 0 || walker.Position() > len(data) {
			t.Fatalf("position %d outside 0..%d after GoTo", walker.Position(), len(data))
		}
		_, _ = walker.ReadCString()
		_, _ = walker.ReadUint16()
		_, _ = walker.ReadUint32()
		_, _ = walker.ReadUint64()
	})
}
