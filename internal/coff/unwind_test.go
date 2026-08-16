// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package coff

import (
	"encoding/binary"
	"testing"
)

func TestParsePDATAAndXDATA(t *testing.T) {
	object, err := NewObject(MachineAMD64)
	if err != nil {
		t.Fatal(err)
	}
	text := NewSection(".text", make([]byte, 16))
	pdata := NewSection(".pdata", make([]byte, 12))
	xdataBytes := []byte{
		0x01, 0x05, 0x03, 0x25, // version/flags, prologue, slots, frame
		0x05, 0x01, // UWOP_ALLOC_LARGE, form 0
		0x04, 0x00, // 4 * 8 = 32 bytes
		0x01, 0x50, // UWOP_PUSH_NONVOL rbp
		0x00, 0x00, // odd-slot padding
	}
	xdata := NewSection(".xdata", xdataBytes)
	for _, section := range []*Section{text, pdata, xdata} {
		if err := object.AddSection(section); err != nil {
			t.Fatal(err)
		}
	}
	if err := object.AddSymbol(NewFunctionSymbol(text, "entry", 0)); err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(pdata.Data[0:4], 0)
	binary.LittleEndian.PutUint32(pdata.Data[4:8], 16)
	binary.LittleEndian.PutUint32(pdata.Data[8:12], 0)

	rows, err := ParsePDATA(object)
	if err != nil {
		t.Fatalf("ParsePDATA() error = %v", err)
	}
	if len(rows) != 1 || rows[0].Function != "entry" || rows[0].Unwind == nil {
		t.Fatalf("rows = %#v", rows)
	}
	unwind := rows[0].Unwind
	if unwind.Version != 1 || unwind.SizeOfPrologue != 5 || unwind.FrameRegister != 5 || unwind.FrameRegisterOffset != 2 {
		t.Fatalf("unwind header = %#v", unwind)
	}
	if len(unwind.Codes) != 2 || unwind.Codes[0].Operation != UnwindOpAllocLarge || unwind.Codes[0].Value != 32 || unwind.Codes[0].Slots != 2 {
		t.Fatalf("unwind codes = %#v", unwind.Codes)
	}
	if unwind.Codes[1].Operation != UnwindOpPushNonVol || RegisterName(unwind.Codes[1].OpInfo) != "rbp" {
		t.Fatalf("push code = %#v", unwind.Codes[1])
	}
}

func TestParseXDATAExceptionHandlerAndTruncation(t *testing.T) {
	data := []byte{0x09, 0, 0, 0, 0x78, 0x56, 0x34, 0x12}
	section := NewSection(".xdata", data)
	info, err := ParseXDATA(section, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.ExceptionHandler == nil || *info.ExceptionHandler != 0x12345678 {
		t.Fatalf("handler = %#v", info.ExceptionHandler)
	}
	if _, err := ParseXDATA(NewSection(".xdata", []byte{1, 0, 2, 0, 1, 1}), 0); err == nil {
		t.Fatal("truncated xdata unexpectedly parsed")
	}
	if _, err := ParseXDATA(section, uint32(len(data))); err == nil {
		t.Fatal("out-of-range xdata offset unexpectedly parsed")
	}
}
