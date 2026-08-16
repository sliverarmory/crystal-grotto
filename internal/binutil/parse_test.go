// SPDX-License-Identifier: GPL-3.0-only

package binutil

import (
	"math/big"
	"reflect"
	"testing"
)

func TestDecodeNumber(t *testing.T) {
	t.Parallel()
	tests := []struct {
		text    string
		maxBits int
		want    string
	}{
		{text: "0", maxBits: 1, want: "0"},
		{text: "127", maxBits: 8, want: "127"},
		{text: "+127", maxBits: 8, want: "127"},
		{text: "-255", maxBits: 8, want: "-255"},
		{text: "0377", maxBits: 8, want: "255"},
		{text: "0xff", maxBits: 8, want: "255"},
		{text: "#FF", maxBits: 8, want: "255"},
		{text: "0x0102030405060708", maxBits: 64, want: "72623859790382856"},
		// BigInteger accepts the second sign; upstream then applies the first.
		{text: "--1", maxBits: 1, want: "1"},
	}
	for _, test := range tests {
		t.Run(test.text, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeNumber(test.text, test.maxBits)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != test.want {
				t.Fatalf("DecodeNumber(%q) = %s, want %s", test.text, got, test.want)
			}
		})
	}
}

func TestDecodeNumberErrors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		text string
		bits int
	}{
		{text: "", bits: 8},
		{text: "08", bits: 8},
		{text: "0X10", bits: 8},
		{text: "0x", bits: 8},
		{text: "256", bits: 8},
		{text: "-256", bits: 8},
		{text: "0", bits: -1},
	} {
		if _, err := DecodeNumber(test.text, test.bits); err == nil {
			t.Errorf("DecodeNumber(%q, %d) unexpectedly succeeded", test.text, test.bits)
		}
	}
}

func TestLowBits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		bits  uint
		want  uint64
	}{
		{value: "255", bits: 8, want: 0xff},
		{value: "256", bits: 8, want: 0},
		{value: "-1", bits: 8, want: 0xff},
		{value: "-255", bits: 8, want: 1},
		{value: "18446744073709551615", bits: 64, want: ^uint64(0)},
	}
	for _, test := range tests {
		number, ok := new(big.Int).SetString(test.value, 10)
		if !ok {
			t.Fatal("bad test value")
		}
		got, err := LowBits(number, test.bits)
		if err != nil || got != test.want {
			t.Errorf("LowBits(%s, %d) = %#x, %v; want %#x", test.value, test.bits, got, err, test.want)
		}
	}
	if _, err := LowBits(nil, 8); err == nil {
		t.Error("LowBits(nil) unexpectedly succeeded")
	}
	if _, err := LowBits(big.NewInt(1), 0); err == nil {
		t.Error("LowBits width zero unexpectedly succeeded")
	}
}

func TestSplitListAndSet(t *testing.T) {
	t.Parallel()
	listTests := []struct {
		input string
		want  []string
	}{
		{input: "", want: []string{}},
		{input: "a, b,\tc", want: []string{"a", "b", "c"}},
		{input: " a ,, b, ", want: []string{"a", "", "b"}},
		{input: ",a", want: []string{"", "a"}},
		{input: ",", want: []string{}},
	}
	for _, test := range listTests {
		if got := SplitList(test.input); !reflect.DeepEqual(got, test.want) {
			t.Errorf("SplitList(%q) = %#v, want %#v", test.input, got, test.want)
		}
	}
	if got, want := SplitSet("b, a, b, , a"), []string{"b", "a", ""}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SplitSet = %#v, want %#v", got, want)
	}
}

func TestParseKeyValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		key   string
		value string
	}{
		{input: "a=b", key: "a", value: "b"},
		{input: "a=b=c", key: "a", value: "b=c"},
		{input: "=value", key: "", value: "value"},
		{input: "key=", key: "key", value: ""},
	}
	for _, test := range tests {
		key, value, err := ParseKeyValue(test.input)
		if err != nil || key != test.key || value != test.value {
			t.Errorf("ParseKeyValue(%q) = %q, %q, %v", test.input, key, value, err)
		}
	}
	if _, _, err := ParseKeyValue("missing"); err == nil {
		t.Error("ParseKeyValue without equals unexpectedly succeeded")
	}
}

func TestParseRange(t *testing.T) {
	t.Parallel()
	valid := []struct {
		input string
		want  Range
	}{
		{input: "1-2", want: Range{Min: 1, Max: 2}},
		{input: "001-010", want: Range{Min: 1, Max: 10}},
		// Upstream parseInt uses -1 as its failure value.
		{input: "-2", want: Range{Min: -1, Max: 2}},
		{input: "999999999999-2", want: Range{Min: -1, Max: 2}},
	}
	for _, test := range valid {
		got, err := ParseRange(test.input)
		if err != nil || got != test.want {
			t.Errorf("ParseRange(%q) = %+v, %v; want %+v", test.input, got, err, test.want)
		}
	}
	for _, input := range []string{"", "1", "1-", "a-2", "2-1", "1-1", "1-2-3"} {
		if _, err := ParseRange(input); err == nil {
			t.Errorf("ParseRange(%q) unexpectedly succeeded", input)
		}
	}
}

func FuzzDecodeNumber(f *testing.F) {
	for _, seed := range []string{"0", "-1", "0377", "0xff", "#ff", "08", ""} {
		f.Add(seed, uint8(8))
	}
	f.Fuzz(func(t *testing.T, text string, bits uint8) {
		_, _ = DecodeNumber(text, int(bits))
	})
}

func FuzzParsers(f *testing.F) {
	for _, seed := range []string{"a=b", "missing", "1-2", "", "1-2-3"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		_, _, _ = ParseKeyValue(text)
		_, _ = ParseRange(text)
		_ = SplitList(text)
		_ = SplitSet(text)
	})
}
