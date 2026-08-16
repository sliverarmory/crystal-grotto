// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

// Package safety implements the Crystal Palace DangerWalk validation pass.
//
// DangerWalk starts at each dynamic-function-resolver, fixptrs, or fixbss
// helper and follows local code calls and references. Calling dprintf from one
// of those helper contexts is unsafe because OutputDebugStringA exception
// propagation can cross code whose stack and unwind state is being rewritten.
//
// The upstream implementation uses Iced's architecture-specific instruction
// details. Crystal Grotto combines a portable disassembler's instruction
// boundaries with checked COFF relocations and a deliberately small decoder
// for the exact x86/x64 encodings CallWalk consumes. An indirect or malformed
// edge that cannot be resolved is reported as ErrUnproven; it is never silently
// omitted from the safety decision.
package safety
