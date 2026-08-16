// SPDX-License-Identifier: GPL-3.0-only

package binutil

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestHexToBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		text string
		want []byte
	}{
		{name: "empty", text: "", want: []byte{}},
		{name: "mixed case", text: "00aBfF", want: []byte{0x00, 0xab, 0xff}},
		{name: "ASCII spaces only", text: "de ad be ef", want: []byte{0xde, 0xad, 0xbe, 0xef}},
		{name: "signed positive group", text: "+f", want: []byte{0x0f}},
		{name: "signed negative group", text: "-f", want: []byte{0xf1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := HexToBytes(test.text)
			if err != nil {
				t.Fatalf("HexToBytes(%q): %v", test.text, err)
			}
			if !bytes.Equal(got, test.want) {
				t.Fatalf("HexToBytes(%q) = %x, want %x", test.text, got, test.want)
			}
		})
	}
}

func TestHexToBytesErrors(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"0", "abc", "gg", "00\t11"} {
		text := text
		t.Run(text, func(t *testing.T) {
			t.Parallel()
			if _, err := HexToBytes(text); err == nil {
				t.Fatalf("HexToBytes(%q) unexpectedly succeeded", text)
			}
		})
	}
}

func TestBytesToHex(t *testing.T) {
	t.Parallel()
	if got, want := BytesToHex([]byte{0, 1, 0xab, 0xff}), "00 01 ab ff"; got != want {
		t.Fatalf("BytesToHex = %q, want %q", got, want)
	}
	if got := BytesToHex(nil); got != "" {
		t.Fatalf("BytesToHex(nil) = %q, want empty", got)
	}
}

func TestDWORD(t *testing.T) {
	t.Parallel()
	data := []byte{0xaa, 0, 0, 0, 0, 0xbb}
	if err := PutDWORD(data, 1, 0x89abcdef); err != nil {
		t.Fatal(err)
	}
	if got, err := GetDWORD(data, 1); err != nil || got != 0x89abcdef {
		t.Fatalf("GetDWORD = %#x, %v", got, err)
	}
	if data[0] != 0xaa || data[5] != 0xbb {
		t.Fatalf("PutDWORD changed bytes outside target: %x", data)
	}

	for _, offset := range []int{-1, 3, 10} {
		if _, err := GetDWORD(data, offset); !errors.Is(err, ErrBounds) {
			t.Errorf("GetDWORD offset %d error = %v, want ErrBounds", offset, err)
		}
		if err := PutDWORD(data, offset, 1); !errors.Is(err, ErrBounds) {
			t.Errorf("PutDWORD offset %d error = %v, want ErrBounds", offset, err)
		}
	}
}

func TestStringEncodings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  []byte
		want string
	}{
		{name: "UTF-8", got: UTF8("Aé"), want: "41c3a9"},
		{name: "UTF-8 Z", got: UTF8Z("Aé"), want: "41c3a900"},
		{name: "UTF-16LE", got: UTF16LE("Aé"), want: "4100e900"},
		{name: "UTF-16LE supplementary", got: UTF16LE("😀"), want: "3dd800de"},
		{name: "UTF-16LE Z", got: UTF16LEZ("A"), want: "41000000"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := hex.EncodeToString(test.got); got != test.want {
				t.Fatalf("encoding = %s, want %s", got, test.want)
			}
		})
	}
}

func TestTransformsAndPrefixes(t *testing.T) {
	t.Parallel()
	input := []byte{0, 1, 2, 3}
	if got := Reverse(input); !bytes.Equal(got, []byte{3, 2, 1, 0}) {
		t.Fatalf("Reverse = %x", got)
	}
	if !bytes.Equal(input, []byte{0, 1, 2, 3}) {
		t.Fatalf("Reverse mutated input: %x", input)
	}

	if got, err := XORRepeating([]byte{0x00, 0x11, 0x22, 0x33, 0x44}, []byte{0x0f, 0x0e}); err != nil ||
		!bytes.Equal(got, []byte{0x0f, 0x1f, 0x2d, 0x3d, 0x4b}) {
		t.Fatalf("XORRepeating = %x, %v", got, err)
	}
	if _, err := XORRepeating(input, nil); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("XORRepeating empty key error = %v", err)
	}

	length, err := PrependLength([]byte{1, 2, 3})
	if err != nil || !bytes.Equal(length, []byte{3, 0, 0, 0, 1, 2, 3}) {
		t.Fatalf("PrependLength = %x, %v", length, err)
	}
	checksum := PrependChecksum([]byte("Wikipedia"))
	if !bytes.Equal(checksum[:4], []byte{0x98, 0x03, 0xe6, 0x11}) {
		t.Fatalf("PrependChecksum prefix = %x", checksum[:4])
	}
	if got := Adler32([]byte("Wikipedia")); got != 0x11e60398 {
		t.Fatalf("Adler32 = %#x", got)
	}
}

func TestRC4EncryptKnownVector(t *testing.T) {
	t.Parallel()
	got, err := RC4Encrypt([]byte("Key"), []byte("Plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "bbf316e8d940af0ad3"; hex.EncodeToString(got) != want {
		t.Fatalf("RC4 = %x, want %s", got, want)
	}
	plain, err := RC4Encrypt([]byte("Key"), got)
	if err != nil || string(plain) != "Plaintext" {
		t.Fatalf("RC4 decrypt = %q, %v", plain, err)
	}
	if _, err := RC4Encrypt(nil, nil); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("RC4 empty key error = %v", err)
	}
}

func FuzzHexToBytes(f *testing.F) {
	for _, seed := range []string{"", "00", "de ad be ef", "+f", "-f", "abc", "00\t11"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		decoded, err := HexToBytes(text)
		if err != nil {
			return
		}
		roundTrip, err := HexToBytes(BytesToHex(decoded))
		if err != nil {
			t.Fatalf("round trip failed: %v", err)
		}
		if !bytes.Equal(roundTrip, decoded) {
			t.Fatalf("round trip = %x, want %x", roundTrip, decoded)
		}
	})
}
