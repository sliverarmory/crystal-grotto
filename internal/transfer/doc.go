// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

// Package transfer expands Crystal Palace's x64 __transfer linker intrinsic.
//
// A canonical relocated CALL __transfer is replaced by the reverse of its
// containing function's provable PUSH/SUB RSP prologue followed by JMP RCX.
// The immediately following one-byte NOP is consumed, matching upstream.
package transfer
