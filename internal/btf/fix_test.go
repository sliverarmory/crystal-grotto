// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

package btf

import (
	"bytes"
	"context"
	"encoding/hex"
	"reflect"
	"sync"
	"testing"

	"github.com/sliverarmory/crystal-grotto/internal/coff"
	"github.com/sliverarmory/crystal-grotto/internal/x86"
)

func TestFixX86ReferencesExactAndIdempotent(t *testing.T) {
	object, text, helper := x86ReferenceFixture(t)
	relocation := text.Relocations[0]
	report, err := FixX86References(context.Background(), object, helper.Name)
	if err != nil {
		t.Fatalf("FixX86References: %v", err)
	}
	want := mustHex(t, "5152e80d000000b94433221183c10501c85a59c38b442404c3")
	if !bytes.Equal(text.Data, want) {
		t.Fatalf(".text = %x\n want = %x", text.Data, want)
	}
	if report != (FixReport{RewrittenInstructions: 1, RetainedRelocations: 1}) {
		t.Fatalf("report = %#v", report)
	}
	if len(text.Relocations) != 1 || text.Relocations[0] != relocation || relocation.VirtualAddress != 8 {
		t.Fatalf("relocation = %#v", text.Relocations)
	}
	if helper.Value != 20 {
		t.Fatalf("helper value = %d, want 20", helper.Value)
	}

	again, err := FixX86References(context.Background(), object, helper.Name)
	if err != nil {
		t.Fatalf("second FixX86References: %v", err)
	}
	if again != (FixReport{}) || !bytes.Equal(text.Data, want) || relocation.VirtualAddress != 8 || helper.Value != 20 {
		t.Fatalf("second pass changed output: report=%#v data=%x reloc=%d helper=%d", again, text.Data, relocation.VirtualAddress, helper.Value)
	}
}

func TestFixBSSReferencesX86Exact(t *testing.T) {
	object, text, helper := bssFixture(t, coff.MachineI386, mustHex(t, "a100000000c38b442404c3"), 6, 1, coff.RelI386Dir32)
	report, err := FixBSSReferencesX86(context.Background(), object, helper.Name)
	if err != nil {
		t.Fatalf("FixBSSReferencesX86: %v", err)
	}
	want := mustHex(t, "51526a10e80800000083c4045a598b00c38b442404c3")
	if !bytes.Equal(text.Data, want) {
		t.Fatalf(".text = %x\n want = %x", text.Data, want)
	}
	if report != (FixReport{RewrittenInstructions: 1, RemovedRelocations: 1}) || len(text.Relocations) != 0 || helper.Value != 17 {
		t.Fatalf("report=%#v relocations=%d helper=%d", report, len(text.Relocations), helper.Value)
	}
	again, err := FixBSSReferences(context.Background(), object, helper.Name)
	if err != nil || again != (FixReport{}) || !bytes.Equal(text.Data, want) {
		t.Fatalf("idempotent pass: report=%#v err=%v data=%x", again, err, text.Data)
	}
}

func TestFixBSSReferencesX64Exact(t *testing.T) {
	object, text, helper := bssFixture(t, coff.MachineAMD64, mustHex(t, "488b0500000000c3c3"), 8, 3, coff.RelAMD64Rel32)
	report, err := FixBSSReferencesX64(context.Background(), object, helper.Name)
	if err != nil {
		t.Fatalf("FixBSSReferencesX64: %v", err)
	}
	want := mustHex(t, "515241504151415241534883ec28b920000000e8120000004883c428415b415a415941585a59488b00c3c3")
	if !bytes.Equal(text.Data, want) {
		t.Fatalf(".text = %x\n want = %x", text.Data, want)
	}
	if report != (FixReport{RewrittenInstructions: 1, RemovedRelocations: 1}) || len(text.Relocations) != 0 || helper.Value != 42 {
		t.Fatalf("report=%#v relocations=%d helper=%d", report, len(text.Relocations), helper.Value)
	}
	assertDisassembles(t, x86.Mode64, text.Data)
}

func TestFixBSSReferencesX64AlignedFrameUsesTwentyByteShadow(t *testing.T) {
	code := mustHex(t, "4883ec288b05000000004883c428c3c3")
	object, text, helper := bssFixture(t, coff.MachineAMD64, code, 14, 6, coff.RelAMD64Rel32)
	if _, err := FixBSSReferencesX64(context.Background(), object, helper.Name); err != nil {
		t.Fatalf("FixBSSReferencesX64: %v", err)
	}
	if !bytes.Contains(text.Data, []byte{0x48, 0x83, 0xec, 0x20}) {
		t.Fatalf("rewritten code lacks aligned 0x20 shadow allocation: %x", text.Data)
	}
	assertDisassembles(t, x86.Mode64, text.Data)
}

func TestFixSupportedInstructionFamilies(t *testing.T) {
	tests := []struct {
		name        string
		machine     coff.Machine
		instruction string
		reloc       int
		typeValue   uint16
	}{
		{name: "x86 register address", machine: coff.MachineI386, instruction: "bb00000000", reloc: 1, typeValue: coff.RelI386Dir32},
		{name: "x86 add eax", machine: coff.MachineI386, instruction: "0500000000", reloc: 1, typeValue: coff.RelI386Dir32},
		{name: "x86 absolute load", machine: coff.MachineI386, instruction: "8b0d00000000", reloc: 2, typeValue: coff.RelI386Dir32},
		{name: "x86 sign extend", machine: coff.MachineI386, instruction: "0fbe1500000000", reloc: 3, typeValue: coff.RelI386Dir32},
		{name: "x86 store", machine: coff.MachineI386, instruction: "890d00000000", reloc: 2, typeValue: coff.RelI386Dir32},
		{name: "x86 compare reverse", machine: coff.MachineI386, instruction: "3b0d00000000", reloc: 2, typeValue: coff.RelI386Dir32},
		{name: "x86 compare constant", machine: coff.MachineI386, instruction: "813d0000000078563412", reloc: 2, typeValue: coff.RelI386Dir32},
		{name: "x86 indirect call", machine: coff.MachineI386, instruction: "ff1500000000", reloc: 2, typeValue: coff.RelI386Dir32},
		{name: "x86 base load", machine: coff.MachineI386, instruction: "8b9100000000", reloc: 2, typeValue: coff.RelI386Dir32},
		{name: "x86 immediate address store", machine: coff.MachineI386, instruction: "c70100000000", reloc: 2, typeValue: coff.RelI386Dir32},
		{name: "x64 lea", machine: coff.MachineAMD64, instruction: "4c8d0500000000", reloc: 3, typeValue: coff.RelAMD64Rel32},
		{name: "x64 byte load", machine: coff.MachineAMD64, instruction: "0fb60d00000000", reloc: 3, typeValue: coff.RelAMD64Rel32},
		{name: "x64 store", machine: coff.MachineAMD64, instruction: "48890d00000000", reloc: 3, typeValue: coff.RelAMD64Rel32},
		{name: "x64 test", machine: coff.MachineAMD64, instruction: "48850500000000", reloc: 3, typeValue: coff.RelAMD64Rel32},
		{name: "x64 constant store", machine: coff.MachineAMD64, instruction: "48c7050000000078563412", reloc: 3, typeValue: coff.RelAMD64Rel32},
		{name: "x64 indirect call", machine: coff.MachineAMD64, instruction: "ff1500000000", reloc: 2, typeValue: coff.RelAMD64Rel32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction := mustHex(t, test.instruction)
			pass := passBSSX86
			if test.machine == coff.MachineAMD64 {
				pass = passBSSX64
			}
			encoding, err := decodeEasyEncoding(instruction, test.reloc, pass)
			if err != nil || encoding.form == formInvalid {
				t.Fatalf("decodeEasyEncoding(%x): encoding=%#v err=%v", instruction, encoding, err)
			}
			relocation := &coff.Relocation{Type: test.typeValue}
			if test.machine == coff.MachineAMD64 {
				section := &coff.Section{Object: &coff.Object{Machine: coff.MachineAMD64}}
				relocation.Section = section
			}
			if err := validateRelocationType(pass, relocation); err != nil {
				t.Fatalf("relocation type: %v", err)
			}
		})
	}
}

func TestFixRepairsRelativeBranchAndMovesSymbols(t *testing.T) {
	// jmp over a relocated MOV to the helper. The insertion grows the jump
	// distance from 6 to 20 bytes but remains in rel8 range.
	code := mustHex(t, "eb06a100000000c3c3")
	object, text, helper := bssFixture(t, coff.MachineI386, code, 8, 3, coff.RelI386Dir32)
	if _, err := FixBSSReferencesX86(context.Background(), object, helper.Name); err != nil {
		t.Fatalf("FixBSSReferencesX86: %v", err)
	}
	if text.Data[0] != 0xeb || text.Data[1] != 17 || helper.Value != 19 {
		t.Fatalf("branch/helper = %x / %d", text.Data[:2], helper.Value)
	}
}

func TestSinglePassesReplayCommandOrder(t *testing.T) {
	object, _ := coff.NewObject(coff.MachineI386)
	text := coff.NewSection(".text", mustHex(t, "a100000000bb00000000c3c38b442404c3"))
	bss := coff.NewSection(".bss", make([]byte, 16))
	data := coff.NewSection(".data", make([]byte, 4))
	for _, section := range []*coff.Section{text, bss, data} {
		if err := object.AddSection(section); err != nil {
			t.Fatal(err)
		}
	}
	entry := coff.NewFunctionSymbol(text, "go", 0)
	getBSS := coff.NewFunctionSymbol(text, "getbss", 11)
	getReturn := coff.NewFunctionSymbol(text, "getret", 12)
	global := coff.NewDataSymbol(data, "global", 0)
	for _, symbol := range []*coff.Symbol{entry, getBSS, getReturn, global} {
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
	}
	text.Relocations = []*coff.Relocation{
		{Section: text, VirtualAddress: 1, SymbolName: ".bss", Symbol: object.GetSymbol(".bss"), Type: coff.RelI386Dir32},
		{Section: text, VirtualAddress: 6, SymbolName: global.Name, Symbol: global, Type: coff.RelI386Dir32},
	}

	bssReport, err := FixBSSReferencesX86(context.Background(), object, getBSS.Name)
	if err != nil {
		t.Fatalf("fixbss: %v", err)
	}
	ptrReport, err := FixX86References(context.Background(), object, getReturn.Name)
	if err != nil {
		t.Fatalf("fixptrs: %v", err)
	}
	if bssReport.RewrittenInstructions != 1 || bssReport.RemovedRelocations != 1 || ptrReport.RewrittenInstructions != 1 || ptrReport.RetainedRelocations != 1 {
		t.Fatalf("reports = %#v, %#v", bssReport, ptrReport)
	}
	if len(text.Relocations) != 1 || text.Relocations[0].SymbolName != global.Name {
		t.Fatalf("relocations after replay = %#v", text.Relocations)
	}
	assertDisassembles(t, x86.Mode32, text.Data)
}

func TestRelocationRemoteOffsetUsesJavaIntWrap(t *testing.T) {
	object, _ := coff.NewObject(coff.MachineI386)
	text := coff.NewSection(".text", []byte{2, 0, 0, 0})
	data := coff.NewSection(".data", nil)
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSection(data); err != nil {
		t.Fatal(err)
	}
	symbol := coff.NewDataSymbol(data, "wrapped", 0x7fffffff)
	if err := object.AddSymbol(symbol); err != nil {
		t.Fatal(err)
	}
	relocation := &coff.Relocation{Section: text, Symbol: symbol}
	got, err := relocationRemoteOffset(object, relocation)
	if err != nil || got != -2147483647 {
		t.Fatalf("relocationRemoteOffset = %d, %v", got, err)
	}
}

func TestApplyEasyPICFixesRollsBackAcrossPasses(t *testing.T) {
	object, _ := coff.NewObject(coff.MachineI386)
	text := coff.NewSection(".text", mustHex(t, "a100000000e900000000c3c38b442404c3"))
	bss := coff.NewSection(".bss", make([]byte, 16))
	data := coff.NewSection(".data", nil)
	for _, section := range []*coff.Section{text, bss, data} {
		if err := object.AddSection(section); err != nil {
			t.Fatal(err)
		}
	}
	entry := coff.NewFunctionSymbol(text, "go", 0)
	getBSS := coff.NewFunctionSymbol(text, "getbss", 11)
	getReturn := coff.NewFunctionSymbol(text, "getret", 12)
	global := coff.NewDataSymbol(data, "global", 0)
	for _, symbol := range []*coff.Symbol{entry, getBSS, getReturn, global} {
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
	}
	bssRelocation := &coff.Relocation{Section: text, VirtualAddress: 1, SymbolName: ".bss", Symbol: object.GetSymbol(".bss"), Type: coff.RelI386Dir32}
	globalRelocation := &coff.Relocation{Section: text, VirtualAddress: 6, SymbolName: global.Name, Symbol: global, Type: coff.RelI386Dir32}
	text.Relocations = []*coff.Relocation{bssRelocation, globalRelocation}
	before := append([]byte(nil), text.Data...)
	if _, err := ApplyEasyPICFixes(context.Background(), object, EasyPICOptions{GetBSS: getBSS.Name, ReturnAddress: getReturn.Name}); err == nil {
		t.Fatal("ApplyEasyPICFixes succeeded with unsupported relocated JMP")
	}
	if !bytes.Equal(text.Data, before) || !reflect.DeepEqual(text.Relocations, []*coff.Relocation{bssRelocation, globalRelocation}) ||
		bssRelocation.VirtualAddress != 1 || globalRelocation.VirtualAddress != 6 || getBSS.Value != 11 || getReturn.Value != 12 {
		t.Fatalf("aggregate rollback failed: data=%x reloc=%#v helpers=%d,%d", text.Data, text.Relocations, getBSS.Value, getReturn.Value)
	}
}

func TestFixRejectsUnsupportedTransactionally(t *testing.T) {
	object, text, helper := bssFixture(t, coff.MachineAMD64, mustHex(t, "488b8300000000c3c3"), 8, 3, coff.RelAMD64Rel32)
	beforeData := append([]byte(nil), text.Data...)
	beforeRelocations := append([]*coff.Relocation(nil), text.Relocations...)
	beforeHelper := helper.Value
	if _, err := FixBSSReferencesX64(context.Background(), object, helper.Name); err == nil || !bytes.Contains([]byte(err.Error()), []byte("not RIP-relative")) {
		t.Fatalf("error = %v", err)
	}
	if !bytes.Equal(text.Data, beforeData) || !reflect.DeepEqual(text.Relocations, beforeRelocations) || helper.Value != beforeHelper {
		t.Fatal("failed transactional pass mutated object")
	}
}

func TestFixRejectsLiveFlagsTransactionally(t *testing.T) {
	// MOV is flags-neutral, so the helper's ADD would corrupt flags observed by JE.
	code := mustHex(t, "a1000000007401c3c3")
	object, text, helper := bssFixture(t, coff.MachineI386, code, 8, 1, coff.RelI386Dir32)
	before := append([]byte(nil), text.Data...)
	if _, err := FixBSSReferencesX86(context.Background(), object, helper.Name); err == nil || !bytes.Contains([]byte(err.Error()), []byte("live flags")) {
		t.Fatalf("error = %v", err)
	}
	if !bytes.Equal(text.Data, before) || len(text.Relocations) != 1 || helper.Value != 8 {
		t.Fatal("live-flags rejection was not transactional")
	}
}

func TestFixValidation(t *testing.T) {
	valid, _, helper := bssFixture(t, coff.MachineI386, mustHex(t, "a100000000c3c3"), 6, 1, coff.RelI386Dir32)
	tests := []struct {
		name string
		call func() error
	}{
		{name: "nil context", call: func() error { _, err := FixBSSReferencesX86(nil, valid, helper.Name); return err }},
		{name: "nil object", call: func() error { _, err := FixBSSReferences(context.Background(), nil, helper.Name); return err }},
		{name: "wrong x86 machine", call: func() error { _, err := FixBSSReferencesX64(context.Background(), valid, helper.Name); return err }},
		{name: "wrong fixptr machine", call: func() error {
			object, _, h := bssFixture(t, coff.MachineAMD64, mustHex(t, "c3c3"), 1, 0, coff.RelAMD64Rel32)
			object.GetSection(".text").Relocations = nil
			_, err := FixX86References(context.Background(), object, h.Name)
			return err
		}},
		{name: "missing helper", call: func() error {
			object, _, _ := bssFixture(t, coff.MachineI386, mustHex(t, "c3"), 0, 0, coff.RelI386Dir32)
			object.GetSection(".text").Relocations = nil
			_, err := FixBSSReferencesX86(context.Background(), object, "missing")
			return err
		}},
		{name: "non-function helper", call: func() error {
			object, _, h := bssFixture(t, coff.MachineI386, mustHex(t, "c3c3"), 1, 0, coff.RelI386Dir32)
			object.GetSection(".text").Relocations = nil
			h.Type = 0
			_, err := FixBSSReferencesX86(context.Background(), object, h.Name)
			return err
		}},
		{name: "missing bss", call: func() error {
			object, _ := coff.NewObject(coff.MachineI386)
			text := coff.NewSection(".text", []byte{0xc3})
			_ = object.AddSection(text)
			h := coff.NewFunctionSymbol(text, "helper", 0)
			_ = object.AddSymbol(h)
			_, err := FixBSSReferencesX86(context.Background(), object, h.Name)
			return err
		}},
		{name: "malformed text", call: func() error {
			object, text, h := bssFixture(t, coff.MachineI386, []byte{0x0f}, 0, 0, coff.RelI386Dir32)
			text.Relocations = nil
			_, err := FixBSSReferencesX86(context.Background(), object, h.Name)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("call succeeded")
			}
		})
	}
}

func TestFixConcurrentCallsOnOneObject(t *testing.T) {
	const workers = 4
	object, text, helper := bssFixture(t, coff.MachineI386, mustHex(t, "a100000000c38b442404c3"), 6, 1, coff.RelI386Dir32)
	var wait sync.WaitGroup
	results := make(chan FixReport, workers)
	errors := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			report, err := FixBSSReferencesX86(context.Background(), object, helper.Name)
			if err != nil {
				errors <- err
				return
			}
			results <- report
		}()
	}
	wait.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	rewritten := 0
	for report := range results {
		rewritten += report.RewrittenInstructions
	}
	if rewritten != 1 || len(text.Relocations) != 0 {
		t.Fatalf("concurrent reports rewrote %d instructions; relocations=%d", rewritten, len(text.Relocations))
	}
}

func FuzzDecodeEasyEncoding(f *testing.F) {
	for _, seed := range [][]byte{
		mustHex(f, "a100000000"),
		mustHex(f, "488b0500000000"),
		mustHex(f, "813d0000000001000000"),
		{0x0f},
	} {
		f.Add(seed, uint8(1), uint8(passBSSX86))
	}
	f.Fuzz(func(t *testing.T, raw []byte, relocation uint8, passValue uint8) {
		pass := fixPass(passValue%3 + 1)
		_, _ = decodeEasyEncoding(raw, int(relocation), pass)
	})
}

func x86ReferenceFixture(t testing.TB) (*coff.Object, *coff.Section, *coff.Symbol) {
	t.Helper()
	object, _ := coff.NewObject(coff.MachineI386)
	text := coff.NewSection(".text", mustHex(t, "b844332211c38b442404c3"))
	data := coff.NewSection(".data", make([]byte, 4))
	if err := object.AddSection(text); err != nil {
		t.Fatal(err)
	}
	if err := object.AddSection(data); err != nil {
		t.Fatal(err)
	}
	entry := coff.NewFunctionSymbol(text, "_go", 0)
	helper := coff.NewFunctionSymbol(text, "_getret", 6)
	target := coff.NewDataSymbol(data, "global", 0)
	for _, symbol := range []*coff.Symbol{entry, helper, target} {
		if err := object.AddSymbol(symbol); err != nil {
			t.Fatal(err)
		}
	}
	text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: 1, SymbolName: target.Name, Symbol: target, Type: coff.RelI386Dir32}}
	return object, text, helper
}

func bssFixture(t testing.TB, machine coff.Machine, code []byte, helperOffset, relocationOffset uint32, relocationType uint16) (*coff.Object, *coff.Section, *coff.Symbol) {
	t.Helper()
	object, text, helper := bssFixtureNoTest(machine, code, helperOffset, relocationOffset, relocationType)
	if object == nil {
		t.Fatal("fixture construction failed")
	}
	return object, text, helper
}

func bssFixtureNoTest(machine coff.Machine, code []byte, helperOffset, relocationOffset uint32, relocationType uint16) (*coff.Object, *coff.Section, *coff.Symbol) {
	object, err := coff.NewObject(machine)
	if err != nil {
		return nil, nil, nil
	}
	text := coff.NewSection(".text", code)
	bss := coff.NewSection(".bss", make([]byte, 32))
	if machine == coff.MachineI386 {
		bss.Data = bss.Data[:16]
		bss.SizeOfRawData = uint32(len(bss.Data))
	}
	if object.AddSection(text) != nil || object.AddSection(bss) != nil {
		return nil, nil, nil
	}
	entry := coff.NewFunctionSymbol(text, "go", 0)
	helper := coff.NewFunctionSymbol(text, "getbss", helperOffset)
	if object.AddSymbol(entry) != nil || object.AddSymbol(helper) != nil {
		return nil, nil, nil
	}
	sectionSymbol := object.GetSymbol(".bss")
	text.Relocations = []*coff.Relocation{{Section: text, VirtualAddress: relocationOffset, SymbolName: sectionSymbol.Name, Symbol: sectionSymbol, Type: relocationType}}
	return object, text, helper
}

func assertDisassembles(t testing.TB, mode x86.Mode, code []byte) {
	t.Helper()
	decoder, err := x86.NewCapstone(context.Background(), mode)
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close(context.Background())
	if _, err := decoder.Disassemble(context.Background(), code, 0); err != nil {
		t.Fatalf("rewritten bytes do not disassemble: %v\n%x", err, code)
	}
}

type fataler interface {
	Helper()
	Fatalf(string, ...any)
}

func mustHex(t fataler, value string) []byte {
	t.Helper()
	result, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return result
}
