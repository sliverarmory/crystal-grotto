// SPDX-License-Identifier: GPL-3.0-only

package hooks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestCatchValidationPrecedenceAndAtomicity(t *testing.T) {
	object := hookTestObject(t, coff.MachineAMD64, "function", "handler", "other", "fourth")
	model := mustNewModel(t, object)
	model = mustApply(t, model, object, "catch", []string{"function", "handler"}, nil)
	if got, ok := model.CatchHandler("function"); !ok || got != "handler" {
		t.Fatalf("CatchHandler = %q,%v", got, ok)
	}
	if !errors.Is(model.CatchEncodingError(), ErrEncoderRequired) {
		t.Fatalf("CatchEncodingError = %v", model.CatchEncodingError())
	}
	tests := []struct {
		arguments []string
		want      string
	}{
		{[]string{"function", "other"}, "Handler handler already defined for function"},
		{[]string{"other", "function"}, "Handler function has handler handler It cannot be a handler."},
		{[]string{"handler", "other"}, "Function handler is a handler. We cannot associate a handler with it"},
		{[]string{"fourth", "fourth"}, "cannot handle exceptions for itself"},
	}
	for _, test := range tests {
		before := model.Snapshot()
		_, err := applyCommand(context.Background(), model, object, "catch", test.arguments, nil)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("catch %#v error = %v, want %q", test.arguments, err, test.want)
		}
		if got := model.Snapshot(); len(got.Catches) != len(before.Catches) {
			t.Fatal("failed catch mutated model")
		}
	}
}

func TestCatchX86OnlyCheckPrecedesSymbolValidation(t *testing.T) {
	object := hookTestObject(t, coff.MachineI386, "_function")
	model := mustNewModel(t, object)
	_, err := applyCommand(context.Background(), model, object, "catch", []string{"missing", "also_missing"}, nil)
	if err == nil || err.Error() != "catch is x64-only" {
		t.Fatalf("x86 catch error = %v", err)
	}
}
