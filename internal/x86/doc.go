// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.
// See LICENSE.upstream.

// Package x86 provides portable, deterministic x86 and x86-64 disassembly.
//
// The Capstone implementation uses github.com/moloch--/go-capstone, whose
// embedded WebAssembly engine avoids a C toolchain and native shared-library
// dependency. A decoder owns one engine and must be closed when it is no longer
// needed. Its methods are safe for concurrent use.
//
// # Iced compatibility boundary
//
// Crystal Palace uses Iced's instruction model throughout its BTF analysis and
// rewrite pipeline. go-capstone v0.0.1 exposes instruction addresses, bytes,
// mnemonics, formatted operands, generic instruction IDs, and alias flags, but
// does not map architecture-specific cs_detail structures into Go. Consequently
// this package cannot yet provide Iced's canonical opcode forms (for example,
// "CALL rel32"), operand kinds and access modes, constant displacement and
// immediate offsets, register and memory read/write sets, memory size/base/index/
// scale/segment data, IP-relative classification, branch-flow classification,
// condition-code and RFLAGS effects, stack-pointer increments, CPUID features,
// or exact Iced Code and Encoding identifiers. Form is therefore empty and
// Instruction.Detail contains only the generic metadata actually exposed by the
// binding.
//
// Capstone also does not replace Iced's instruction copying, mutation,
// relocation-aware symbol formatting, or assembler/encoder APIs. BTF passes
// that depend on any of those semantics must remain disabled until a backend
// exposes equivalent typed detail; formatted operand text must not be parsed as
// a substitute for semantic operands.
package x86
