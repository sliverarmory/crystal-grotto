// SPDX-License-Identifier: GPL-3.0-only

package hooks

import (
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestCheckFunctionAndX86Suggestions(t *testing.T) {
	object := hookTestObject(t, coff.MachineI386, "_plain", "_stdcall@8", "naked@4")
	data := coff.NewDataSymbol(object.GetSection(".text"), "data", 0)
	if err := object.AddSymbol(data); err != nil {
		t.Fatal(err)
	}
	for _, symbol := range []string{"_plain", "_stdcall@8", "naked@4"} {
		if err := CheckFunction(object, symbol); err != nil {
			t.Fatalf("CheckFunction(%q): %v", symbol, err)
		}
	}
	tests := []struct {
		symbol string
		want   string
	}{
		{"plain", "Did you mean _plain?"},
		{"stdcall", "Did you mean _stdcall@8?"},
		{"naked", "Did you mean naked@4?"},
		{"missing", "Symbol missing does not exist."},
		{"data", "Symbol data is not a function."},
	}
	for _, test := range tests {
		err := CheckFunction(object, test.symbol)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("CheckFunction(%q) error = %v, want %q", test.symbol, err, test.want)
		}
	}
	if err := CheckFunction(nil, "x"); err != ErrNilObject {
		t.Fatalf("nil object error = %v", err)
	}
}
