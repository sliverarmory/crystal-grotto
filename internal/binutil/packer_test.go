// SPDX-License-Identifier: GPL-3.0-only

package binutil

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPackerByteOrderAndNarrowing(t *testing.T) {
	t.Parallel()
	var zero Packer
	zero.AddShort(0x1234)
	if got := hex.EncodeToString(zero.Bytes()); got != "1234" {
		t.Fatalf("zero-value Packer = %s, want big-endian 1234", got)
	}

	big := NewPacker()
	big.AddShort(0x1234)
	big.AddInt(0x01020304)
	big.AddLong(0x0102030405060708)
	if got, want := hex.EncodeToString(big.Bytes()), "1234010203040102030405060708"; got != want {
		t.Fatalf("big pack = %s, want %s", got, want)
	}

	little := NewPacker().Little()
	little.AddByte(-1)
	little.AddShort(-2)
	little.AddUShort(0x12345)
	little.AddInt(0x89abcdef)
	little.AddLong(0x0102030405060708)
	if got, want := hex.EncodeToString(little.Bytes()), "fffeff4523efcdab890807060504030201"; got != want {
		t.Fatalf("little pack = %s, want %s", got, want)
	}
}

func TestPackerDataAndStrings(t *testing.T) {
	t.Parallel()
	packer := NewPacker().Little()
	if err := packer.AddData([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	packer.AddDataVerify([]byte("Wikipedia"))
	if err := packer.AddUTF8String("A"); err != nil {
		t.Fatal(err)
	}
	if err := packer.AddWideString("B"); err != nil {
		t.Fatal(err)
	}
	wantPrefix := []byte{3, 0, 0, 0, 1, 2, 3, 0x98, 0x03, 0xe6, 0x11}
	if !bytes.HasPrefix(packer.Bytes(), wantPrefix) {
		t.Fatalf("packed prefix = %x", packer.Bytes())
	}
	if got, want := hex.EncodeToString(packer.Bytes()[20:]), "0200000041000400000042000000"; got != want {
		t.Fatalf("packed strings = %s, want %s", got, want)
	}
	copyOut := packer.Bytes()
	copyOut[0] = 0xff
	if packer.Bytes()[0] == 0xff {
		t.Fatal("Bytes returned an alias")
	}
	if err := packer.Pad(-1); err == nil {
		t.Fatal("negative Pad unexpectedly succeeded")
	}
}

func TestConcat(t *testing.T) {
	t.Parallel()
	first := []byte{1, 2, 3}
	concat, err := NewConcat(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := concat.Align(4); err != nil {
		t.Fatal(err)
	}
	if err := concat.AddByte(5); err != nil {
		t.Fatal(err)
	}
	if got, want := concat.Bytes(), []byte{1, 2, 3, 0, 5}; !bytes.Equal(got, want) {
		t.Fatalf("Concat = %v, want %v", got, want)
	}
	first[0] = 9
	if concat.Bytes()[0] != 9 {
		t.Fatal("Concat did not preserve upstream add-by-reference behavior")
	}
	if err := concat.Pad(2); err != nil {
		t.Fatal(err)
	}
	if concat.Length() != 7 || len(concat.Bytes()) != 5 {
		t.Fatalf("virtual Pad contract: Length=%d len(Bytes)=%d", concat.Length(), len(concat.Bytes()))
	}
	if err := concat.Align(0); err == nil {
		t.Fatal("zero alignment unexpectedly succeeded")
	}
}
