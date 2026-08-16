// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

package coff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	UnwindFlagEHandler  uint8 = 0x01
	UnwindFlagUHandler  uint8 = 0x02
	UnwindFlagChainInfo uint8 = 0x04

	UnwindOpPushNonVol    uint8 = 0
	UnwindOpAllocLarge    uint8 = 1
	UnwindOpAllocSmall    uint8 = 2
	UnwindOpSetFPReg      uint8 = 3
	UnwindOpSaveNonVol    uint8 = 4
	UnwindOpSaveNonVolFar uint8 = 5
	UnwindOpSaveXMM128    uint8 = 8
	UnwindOpSaveXMM128Far uint8 = 9
	UnwindOpPushMachFrame uint8 = 10
)

// RuntimeFunction is one x64 RUNTIME_FUNCTION entry from .pdata.
type RuntimeFunction struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32
	Function     string
	Unwind       *UnwindInfo
}

// UnwindInfo is a decoded x64 UNWIND_INFO record.
type UnwindInfo struct {
	Offset              uint32
	Version             uint8
	Flags               uint8
	SizeOfPrologue      uint8
	CountOfUnwindCodes  uint8
	FrameRegister       uint8
	FrameRegisterOffset uint8
	Codes               []UnwindCode
	ExceptionHandler    *uint32
	ChainedFunction     *RuntimeFunction
}

// UnwindCode represents one operation plus any continuation slots it owns.
type UnwindCode struct {
	CodeOffset uint8
	Operation  uint8
	OpInfo     uint8
	Slots      uint8
	Value      uint32
	RawExtra   []uint16
}

func (c UnwindCode) OperationName() string {
	switch c.Operation {
	case UnwindOpPushNonVol:
		return "UWOP_PUSH_NONVOL"
	case UnwindOpAllocLarge:
		return "UWOP_ALLOC_LARGE"
	case UnwindOpAllocSmall:
		return "UWOP_ALLOC_SMALL"
	case UnwindOpSetFPReg:
		return "UWOP_SET_FPREG"
	case UnwindOpSaveNonVol:
		return "UWOP_SAVE_NONVOL"
	case UnwindOpSaveNonVolFar:
		return "UWOP_SAVE_NONVOL_FAR"
	case UnwindOpSaveXMM128:
		return "UWOP_SAVE_XMM128"
	case UnwindOpSaveXMM128Far:
		return "UWOP_SAVE_XMM128_FAR"
	case UnwindOpPushMachFrame:
		return "UWOP_PUSH_MACHFRAME"
	default:
		return fmt.Sprintf("UWOP_UNKNOWN_%d", c.Operation)
	}
}

// RegisterName returns the Windows x64 unwind register spelling.
func RegisterName(number uint8) string {
	registers := [...]string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
	if int(number) >= len(registers) {
		return "unknown"
	}
	return registers[number]
}

// ParsePDATA parses all twelve-byte RUNTIME_FUNCTION rows and, when an xdata
// section is available, decodes their referenced unwind records.
func ParsePDATA(object *Object) ([]RuntimeFunction, error) {
	if object == nil {
		return nil, errors.New("coff: nil object")
	}
	pdata := object.GetSection(".pdata")
	if pdata == nil {
		return nil, nil
	}
	if len(pdata.Data)%12 != 0 {
		return nil, fmt.Errorf("coff: .pdata length %d is not a multiple of 12", len(pdata.Data))
	}
	functionNames := make(map[uint32]string)
	if text := object.GetSection(".text"); text != nil {
		for _, symbol := range text.SymbolsSorted() {
			functionNames[symbol.Value] = symbol.Name
		}
	}
	var xdata *Section
	for _, section := range object.Sections {
		if strings.HasPrefix(section.Name, ".xdata") {
			xdata = section
			break
		}
	}
	rows := make([]RuntimeFunction, 0, len(pdata.Data)/12)
	for offset := 0; offset < len(pdata.Data); offset += 12 {
		row := RuntimeFunction{
			BeginAddress: binary.LittleEndian.Uint32(pdata.Data[offset : offset+4]),
			EndAddress:   binary.LittleEndian.Uint32(pdata.Data[offset+4 : offset+8]),
			UnwindData:   binary.LittleEndian.Uint32(pdata.Data[offset+8 : offset+12]),
		}
		row.Function = functionNames[row.BeginAddress]
		if xdata != nil {
			unwind, err := ParseXDATA(xdata, row.UnwindData)
			if err != nil {
				return nil, fmt.Errorf("coff: .pdata row %d: %w", offset/12, err)
			}
			row.Unwind = unwind
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// ParseXDATA parses a single UNWIND_INFO record at a section-relative offset.
func ParseXDATA(section *Section, offset uint32) (*UnwindInfo, error) {
	if section == nil {
		return nil, errors.New("coff: nil xdata section")
	}
	start := uint64(offset)
	if start+4 > uint64(len(section.Data)) {
		return nil, fmt.Errorf("xdata offset %#x is outside section %q", offset, section.Name)
	}
	data := section.Data
	first := data[offset]
	frame := data[offset+3]
	info := &UnwindInfo{
		Offset:              offset,
		Version:             first & 0x07,
		Flags:               first >> 3,
		SizeOfPrologue:      data[offset+1],
		CountOfUnwindCodes:  data[offset+2],
		FrameRegister:       frame & 0x0f,
		FrameRegisterOffset: frame >> 4,
	}

	codeBase := uint64(offset) + 4
	codeBytes := uint64(info.CountOfUnwindCodes) * 2
	if codeBase+codeBytes > uint64(len(data)) {
		return nil, fmt.Errorf("xdata unwind-code array at %#x extends beyond section %q", offset, section.Name)
	}
	for slot := uint8(0); slot < info.CountOfUnwindCodes; {
		position := codeBase + uint64(slot)*2
		code := UnwindCode{
			CodeOffset: data[position],
			Operation:  data[position+1] & 0x0f,
			OpInfo:     data[position+1] >> 4,
			Slots:      1,
		}
		extraSlots := unwindExtraSlots(code.Operation, code.OpInfo)
		if uint16(slot)+1+uint16(extraSlots) > uint16(info.CountOfUnwindCodes) {
			return nil, fmt.Errorf("xdata operation %s at slot %d exceeds declared unwind-code count", code.OperationName(), slot)
		}
		for extra := uint8(0); extra < extraSlots; extra++ {
			extraPosition := position + 2 + uint64(extra)*2
			code.RawExtra = append(code.RawExtra, binary.LittleEndian.Uint16(data[extraPosition:extraPosition+2]))
		}
		code.Slots += extraSlots
		code.Value = unwindValue(code)
		info.Codes = append(info.Codes, code)
		slot += code.Slots
	}

	trailer := codeBase + codeBytes
	if info.CountOfUnwindCodes%2 != 0 {
		trailer += 2
	}
	if info.Flags&(UnwindFlagEHandler|UnwindFlagUHandler) != 0 {
		if trailer+4 > uint64(len(data)) {
			return nil, fmt.Errorf("xdata exception handler at %#x extends beyond section %q", trailer, section.Name)
		}
		value := binary.LittleEndian.Uint32(data[trailer : trailer+4])
		info.ExceptionHandler = &value
	}
	if info.Flags&UnwindFlagChainInfo != 0 {
		if trailer+12 > uint64(len(data)) {
			return nil, fmt.Errorf("xdata chained runtime function at %#x extends beyond section %q", trailer, section.Name)
		}
		info.ChainedFunction = &RuntimeFunction{
			BeginAddress: binary.LittleEndian.Uint32(data[trailer : trailer+4]),
			EndAddress:   binary.LittleEndian.Uint32(data[trailer+4 : trailer+8]),
			UnwindData:   binary.LittleEndian.Uint32(data[trailer+8 : trailer+12]),
		}
	}
	return info, nil
}

func unwindExtraSlots(operation, opInfo uint8) uint8 {
	switch operation {
	case UnwindOpAllocLarge:
		if opInfo == 0 {
			return 1
		}
		return 2
	case UnwindOpSaveNonVol, UnwindOpSaveXMM128:
		return 1
	case UnwindOpSaveNonVolFar, UnwindOpSaveXMM128Far:
		return 2
	default:
		return 0
	}
}

func unwindValue(code UnwindCode) uint32 {
	if len(code.RawExtra) == 0 {
		if code.Operation == UnwindOpAllocSmall {
			return uint32(code.OpInfo)*8 + 8
		}
		return 0
	}
	value := uint32(code.RawExtra[0])
	if len(code.RawExtra) == 2 {
		value |= uint32(code.RawExtra[1]) << 16
	}
	switch code.Operation {
	case UnwindOpAllocLarge:
		if code.OpInfo == 0 {
			return value * 8
		}
		return value
	case UnwindOpSaveNonVol:
		return value * 8
	case UnwindOpSaveXMM128:
		return value * 16
	default:
		return value
	}
}
