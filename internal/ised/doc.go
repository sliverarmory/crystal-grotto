// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

// Package ised models Crystal Palace's instruction-search-and-edit (ised)
// configuration, trie matching, safety selection, and rewrite boundary.
//
// Commands are parsed and accumulated independently from an object. BuildPlan
// then matches canonical Iced-style opcode forms, their mnemonic head, and MASM
// assembly text over each function without allowing patterns to cross function
// boundaries. It preserves the upstream +before, +after, +first, +last, +safe,
// and +split semantics. Candidate commands are shuffled with injectable
// randomness before one eligible edit is selected for each instruction phase.
//
// # Decoder and encoder boundary
//
// Crystal Palace gets canonical opcode forms, flag producer/consumer zones,
// prologue/epilogue bookends, and relocation-aware instruction encoding from
// Iced. The current Capstone adapter in internal/x86 does not expose equivalent
// typed detail. BuildPlan therefore requires callers to supply those semantics
// explicitly and returns ErrSemanticDetailUnavailable when a canonical Form or
// assembly rendering is missing; formatted Capstone operands are never guessed
// into an Iced form.
//
// Apply is transactional and delegates arbitrary length-changing object edits
// to RewriteBackend. FixedBackend is built in for the provable subset whose
// selected bytes occupy exactly the original instruction span. It deliberately
// returns ErrReencoderUnavailable instead of shifting code without repairing
// branches, symbols, unwind ranges, and relocations.
//
// In the upstream export pipeline ised runs after intrinsic/hook rewriting,
// easy-PIC/DFR resolution, ordering/rule analysis, and +mutate; it runs before
// +regdance and the final +blockparty/+shatter jump-healing pass.
package ised
