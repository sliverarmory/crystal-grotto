// SPDX-License-Identifier: GPL-3.0-only

package x86

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sync"
	"testing"
)

func TestCapstoneDisassemble(t *testing.T) {
	tests := []struct {
		name    string
		mode    Mode
		address uint64
		code    []byte
		want    []Instruction
	}{
		{
			name:    "x86",
			mode:    Mode32,
			address: 0x00401000,
			code:    []byte{0x55, 0x89, 0xe5, 0x83, 0xec, 0x10, 0xe8, 0x78, 0x56, 0x34, 0x12, 0xc3},
			want: []Instruction{
				{Address: 0x00401000, Bytes: []byte{0x55}, Mnemonic: "push", Operands: "ebp"},
				{Address: 0x00401001, Bytes: []byte{0x89, 0xe5}, Mnemonic: "mov", Operands: "ebp, esp"},
				{Address: 0x00401003, Bytes: []byte{0x83, 0xec, 0x10}, Mnemonic: "sub", Operands: "esp, 0x10"},
				{Address: 0x00401006, Bytes: []byte{0xe8, 0x78, 0x56, 0x34, 0x12}, Mnemonic: "call", Operands: "0x12746683"},
				{Address: 0x0040100b, Bytes: []byte{0xc3}, Mnemonic: "ret"},
			},
		},
		{
			name:    "x64",
			mode:    Mode64,
			address: 0x140001000,
			code:    []byte{0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x05, 0x34, 0x12, 0x00, 0x00, 0x48, 0x83, 0xec, 0x20, 0xc3},
			want: []Instruction{
				{Address: 0x140001000, Bytes: []byte{0x55}, Mnemonic: "push", Operands: "rbp"},
				{Address: 0x140001001, Bytes: []byte{0x48, 0x89, 0xe5}, Mnemonic: "mov", Operands: "rbp, rsp"},
				{Address: 0x140001004, Bytes: []byte{0x48, 0x8d, 0x05, 0x34, 0x12, 0x00, 0x00}, Mnemonic: "lea", Operands: "rax, [rip + 0x1234]"},
				{Address: 0x14000100b, Bytes: []byte{0x48, 0x83, 0xec, 0x20}, Mnemonic: "sub", Operands: "rsp, 0x20"},
				{Address: 0x14000100f, Bytes: []byte{0xc3}, Mnemonic: "ret"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder := openTestCapstone(t, test.mode)
			got, err := decoder.Disassemble(context.Background(), test.code, test.address)
			if err != nil {
				t.Fatalf("Disassemble: %v", err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("instruction count = %d, want %d", len(got), len(test.want))
			}
			for index := range test.want {
				assertInstruction(t, index, got[index], test.want[index])
			}

			// Returned bytes must not alias caller-owned input.
			first := got[0].Bytes[0]
			test.code[0] ^= 0xff
			if got[0].Bytes[0] != first {
				t.Fatal("decoded bytes alias input")
			}
		})
	}
}

func assertInstruction(t *testing.T, index int, got, want Instruction) {
	t.Helper()
	if got.Address != want.Address || !bytes.Equal(got.Bytes, want.Bytes) || got.Mnemonic != want.Mnemonic || got.Operands != want.Operands {
		t.Errorf("instruction[%d] = {%#x %x %q %q}, want {%#x %x %q %q}",
			index, got.Address, got.Bytes, got.Mnemonic, got.Operands,
			want.Address, want.Bytes, want.Mnemonic, want.Operands)
	}
	if got.Form != "" {
		t.Errorf("instruction[%d].Form = %q, want unavailable", index, got.Form)
	}
	if got.Detail == nil || got.Detail.InstructionID == 0 {
		t.Errorf("instruction[%d] missing generic Capstone detail: %#v", index, got.Detail)
	}
}

func TestCapstoneRejectsInvalidAndTruncatedInput(t *testing.T) {
	tests := []struct {
		name       string
		code       []byte
		wantOffset int
	}{
		{name: "truncated first instruction", code: []byte{0x0f}, wantOffset: 0},
		{name: "truncated after valid prefix", code: []byte{0x90, 0x0f}, wantOffset: 1},
		{
			name:       "instruction longer than architectural maximum",
			code:       []byte{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x90},
			wantOffset: 0,
		},
	}

	decoder := openTestCapstone(t, Mode64)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instructions, err := decoder.Disassemble(context.Background(), test.code, 0x1000)
			if err == nil {
				t.Fatalf("Disassemble returned %d instructions, want error", len(instructions))
			}
			if instructions != nil {
				t.Fatalf("Disassemble returned partial instructions: %#v", instructions)
			}
			if !errors.Is(err, ErrInvalidInstruction) || !IsDecodeError(err) {
				t.Fatalf("error = %v, want DecodeError wrapping ErrInvalidInstruction", err)
			}
			var decodeErr *DecodeError
			if !errors.As(err, &decodeErr) {
				t.Fatalf("error type = %T, want *DecodeError", err)
			}
			if decodeErr.Offset != test.wantOffset || decodeErr.Address != 0x1000+uint64(test.wantOffset) {
				t.Errorf("DecodeError = offset %#x address %#x, want offset %#x address %#x",
					decodeErr.Offset, decodeErr.Address, test.wantOffset, 0x1000+uint64(test.wantOffset))
			}
			if !bytes.Equal(decodeErr.Remaining, test.code[test.wantOffset:]) {
				t.Errorf("remaining = %x, want %x", decodeErr.Remaining, test.code[test.wantOffset:])
			}
		})
	}
}

func TestCapstoneInputValidation(t *testing.T) {
	modeStrings := []struct {
		mode Mode
		want string
	}{{Mode32, "x86"}, {Mode64, "x64"}, {Mode(0), "unknown-0"}}
	for _, test := range modeStrings {
		if got := test.mode.String(); got != test.want {
			t.Errorf("Mode(%d).String() = %q, want %q", test.mode, got, test.want)
		}
	}
	if _, err := NewCapstone(context.Background(), Mode(16)); !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("NewCapstone invalid mode error = %v, want ErrInvalidMode", err)
	}
	if _, err := NewCapstone(nil, Mode64); !errors.Is(err, ErrNilContext) {
		t.Fatalf("NewCapstone nil context error = %v, want ErrNilContext", err)
	}

	decoder := openTestCapstone(t, Mode64)
	empty, err := decoder.Disassemble(context.Background(), nil, 0)
	if err != nil {
		t.Fatalf("empty Disassemble: %v", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("empty Disassemble = %#v, want empty non-nil slice", empty)
	}
	if _, err := decoder.Disassemble(nil, []byte{0x90}, 0); !errors.Is(err, ErrNilContext) {
		t.Fatalf("nil-context Disassemble error = %v, want ErrNilContext", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := decoder.Disassemble(cancelled, []byte{0x90}, 0); !errors.Is(err, context.Canceled) || IsDecodeError(err) {
		t.Fatalf("cancelled Disassemble error = %v, want context.Canceled and not DecodeError", err)
	}
	if _, err := decoder.Disassemble(context.Background(), []byte{0x90, 0xc3}, math.MaxUint64); !errors.Is(err, ErrAddressOverflow) {
		t.Fatalf("overflow Disassemble error = %v, want ErrAddressOverflow", err)
	}
}

func TestCapstoneConcurrentUse(t *testing.T) {
	decoder := openTestCapstone(t, Mode64)
	code := []byte{0x55, 0x48, 0x89, 0xe5, 0x90, 0xc3}

	const (
		workers    = 12
		iterations = 8
	)
	start := make(chan struct{})
	errorsFromWorkers := make(chan error, workers)
	var workersDone sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		workersDone.Add(1)
		go func() {
			defer workersDone.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				address := uint64(0x1000 + worker*0x100 + iteration*0x10)
				instructions, err := decoder.Disassemble(context.Background(), code, address)
				if err != nil {
					errorsFromWorkers <- err
					return
				}
				if len(instructions) != 4 || instructions[0].Address != address || instructions[3].Mnemonic != "ret" {
					errorsFromWorkers <- errors.New("concurrent decode returned inconsistent instructions")
					return
				}
			}
		}()
	}
	close(start)
	workersDone.Wait()
	close(errorsFromWorkers)
	for err := range errorsFromWorkers {
		t.Error(err)
	}
}

func TestCapstoneCloseLifecycle(t *testing.T) {
	decoder, err := NewCapstone(context.Background(), Mode32)
	if err != nil {
		t.Fatalf("NewCapstone: %v", err)
	}
	if decoder.Mode() != Mode32 || decoder.IsClosed() {
		t.Fatalf("new decoder = mode %s closed %v", decoder.Mode(), decoder.IsClosed())
	}

	// Exercise resource release racing with an in-flight caller. The mutex
	// makes either a complete decode or ErrClosed valid, never partial output.
	start := make(chan struct{})
	decodeResult := make(chan error, 1)
	closeResult := make(chan error, 1)
	go func() {
		<-start
		instructions, decodeErr := decoder.Disassemble(context.Background(), []byte{0x90}, 0)
		if decodeErr == nil && (len(instructions) != 1 || instructions[0].Mnemonic != "nop") {
			decodeErr = errors.New("concurrent close produced incomplete decode")
		}
		decodeResult <- decodeErr
	}()
	go func() {
		<-start
		closeResult <- decoder.Close(context.Background())
	}()
	close(start)
	if err := <-closeResult; err != nil {
		t.Fatalf("concurrent Close: %v", err)
	}
	if err := <-decodeResult; err != nil && !errors.Is(err, ErrClosed) {
		t.Fatalf("concurrent Disassemble error = %v, want success or ErrClosed", err)
	}
	if !decoder.IsClosed() {
		t.Fatal("decoder is not closed")
	}
	if err := decoder.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := decoder.Disassemble(context.Background(), []byte{0x90}, 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("Disassemble after Close error = %v, want ErrClosed", err)
	}
	if _, err := decoder.Disassemble(context.Background(), nil, 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("empty Disassemble after Close error = %v, want ErrClosed", err)
	}
	if err := decoder.Close(nil); !errors.Is(err, ErrNilContext) {
		t.Fatalf("Close nil context error = %v, want ErrNilContext", err)
	}

	var nilDecoder *Capstone
	if err := nilDecoder.Close(context.Background()); err != nil {
		t.Fatalf("nil decoder Close: %v", err)
	}
	if _, err := nilDecoder.Disassemble(context.Background(), []byte{0x90}, 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil decoder Disassemble error = %v, want ErrClosed", err)
	}
	if nilDecoder.Mode() != 0 || !nilDecoder.IsClosed() {
		t.Fatal("nil decoder lifecycle queries are not safe")
	}
}

func TestDecodeErrorDefaults(t *testing.T) {
	err := &DecodeError{Offset: 2, Address: 0x1002, Remaining: []byte{0x0f}}
	want := "x86: invalid or truncated instruction at byte offset 0x2 (address 0x1002, 1 bytes remain)"
	if got := err.Error(); got != want {
		t.Fatalf("DecodeError.Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrInvalidInstruction) {
		t.Fatalf("errors.Is(%v, ErrInvalidInstruction) = false", err)
	}
}

func openTestCapstone(t *testing.T, mode Mode) *Capstone {
	t.Helper()
	decoder, err := NewCapstone(context.Background(), mode)
	if err != nil {
		t.Fatalf("NewCapstone(%s): %v", mode, err)
	}
	t.Cleanup(func() {
		if err := decoder.Close(context.Background()); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return decoder
}
