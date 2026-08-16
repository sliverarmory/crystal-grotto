// SPDX-License-Identifier: GPL-3.0-only

package resolver

import (
	"errors"
	"strings"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
)

func TestApplyIsTransactionalAndValidatesBackend(t *testing.T) {
	t.Parallel()
	newFixture := func(t *testing.T) (*coff.Object, Configuration) {
		t.Helper()
		object := resolverTestObject(t, coff.MachineAMD64, []byte{0xff, 0x15, 0, 0, 0, 0, 0xc3})
		addFunction(t, object, object.GetSection(".text"), "resolve", 6)
		addImportRelocation(t, object, "__imp_KERNEL32$Sleep", 2, coff.RelAMD64Rel32)
		return object, defaultConfiguration(t, object, "resolve", MethodROR13)
	}

	t.Run("no backend", func(t *testing.T) {
		object, configuration := newFixture(t)
		result, plan, err := Apply(object, configuration, nil)
		if !errors.Is(err, ErrReencoderUnavailable) || result != nil || len(plan.Sites) != 1 {
			t.Fatalf("Apply = %#v, %#v, %v", result, plan, err)
		}
		if got := object.GetSection(".text").Data[0]; got != 0xff {
			t.Fatalf("input mutated to %#x", got)
		}
	})

	t.Run("backend error", func(t *testing.T) {
		object, configuration := newFixture(t)
		backendError := errors.New("encoder failed")
		result, _, err := Apply(object, configuration, RewriteBackendFunc(func(candidate *coff.Object, _ RewritePlan) error {
			candidate.GetSection(".text").Data[0] = 0x90
			return backendError
		}))
		if result != nil || !errors.Is(err, backendError) {
			t.Fatalf("Apply result/error = %#v, %v", result, err)
		}
		if object.GetSection(".text").Data[0] != 0xff {
			t.Fatal("failed backend mutated input")
		}
	})

	t.Run("left unresolved", func(t *testing.T) {
		object, configuration := newFixture(t)
		_, _, err := Apply(object, configuration, RewriteBackendFunc(func(candidate *coff.Object, _ RewritePlan) error {
			candidate.GetSection(".text").Data[0] = 0x90
			return nil
		}))
		if err == nil || !strings.Contains(err.Error(), "left") || !strings.Contains(err.Error(), "unresolved") {
			t.Fatalf("unresolved backend error = %v", err)
		}
		if object.GetSection(".text").Data[0] != 0xff {
			t.Fatal("unresolved backend mutated input")
		}
	})

	t.Run("success", func(t *testing.T) {
		object, configuration := newFixture(t)
		result, plan, err := Apply(object, configuration, RewriteBackendFunc(func(candidate *coff.Object, received RewritePlan) error {
			if len(received.Sites) != 1 {
				return errors.New("missing site")
			}
			text := candidate.GetSection(".text")
			text.Data[0] = 0x90
			text.Relocations = nil
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Sites) != 1 || result.GetSection(".text").Data[0] != 0x90 || len(result.GetSection(".text").Relocations) != 0 {
			t.Fatalf("result/plan = %#v / %#v", result, plan)
		}
		if object.GetSection(".text").Data[0] != 0xff || len(object.GetSection(".text").Relocations) != 1 {
			t.Fatal("successful backend mutated input")
		}
	})
}

func TestApplyNoSitesReturnsIndependentValidatedClone(t *testing.T) {
	t.Parallel()
	object := resolverTestObject(t, coff.MachineAMD64, []byte{0xc3})
	addFunction(t, object, object.GetSection(".text"), "go", 0)
	result, plan, err := Apply(object, EmptyConfiguration(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Sites) != 0 || result == object {
		t.Fatalf("result/plan = %#v / %#v", result, plan)
	}
	result.GetSection(".text").Data[0] = 0x90
	if object.GetSection(".text").Data[0] != 0xc3 {
		t.Fatal("result clone shares input data")
	}
}
