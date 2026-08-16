// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

// Package hookencode applies Crystal Palace hook and intrinsic plans to Intel
// COFF objects.
//
// Apply follows Crystal Palace's pass order: intrinsics, local redirects, then
// imported API attaches. Policy remains in hooks.Model; this package only
// classifies and encodes sites selected by that immutable model.
//
// Every supported replacement is the same length as its source instruction.
// Consequently unrelated symbols, relocations, local branches, pdata ranges,
// and xdata references retain their offsets. The package does not regenerate
// Windows unwind programs. A same-length user intrinsic that changes a
// function prologue can therefore make existing unwind instructions describe
// different machine code; callers and intrinsic authors remain responsible
// for that semantic constraint. Unequal-length intrinsics and __resolve_hook
// expansion fail with typed errors instead of being approximated.
//
// This fixed-layout contract is semantically compatible with the supported
// Attach forms but intentionally differs from Iced's byte layout in two cases:
// a six-byte indirect call/jump becomes NOP plus a five-byte direct branch, and
// an imported-address load followed by CALL through that register is not fused
// into one direct CALL. Both sequences retain call-versus-tail-call behavior
// and reach the wrapper chosen by hooks.Model without moving fallthrough code.
package hookencode
