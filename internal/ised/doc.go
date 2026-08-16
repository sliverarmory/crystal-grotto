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
// # Object lift and rewrite
//
// Crystal Palace gets canonical opcode forms, flag producer/consumer zones,
// prologue/epilogue bookends, and relocation-aware instruction encoding from
// Iced. LiftObject combines Capstone's authoritative instruction boundaries
// with a conservative raw-byte semantic decoder for common x86/x64 forms. It
// exposes exact form/mnemonic keys whenever those are proven, exact MASM keys
// only for the small register/implied-operand subset whose spelling is proven,
// and marks everything else incomplete. BuildPlan permits unrelated commands
// to pass such instructions but returns ErrSemanticDetailUnavailable whenever
// a requested key could depend on missing Iced detail. Formatted Capstone
// operands are never converted into semantic operands or targets.
//
// ApplyObject is the engine-facing transactional operation. RebaseBackend
// supports raw insert, replace, and split output while rebasing proven relative
// branches/RIP references, symbols, relocations, section-symbol addends,
// function auxiliary sizes, and relocation-backed pdata ranges. Ordinary jump
// targets follow upstream's post-prepend label placement while named local
// labels retain the pre-prepend function/data address. Existing pdata requires
// unwind-aware planning, whose byte-derived bookend walk follows upstream.
// Unknown PC-relative forms, unrelocated unwind ranges, unsupported relocation
// widths, and branches that would require form relaxation fail with typed
// errors; injected bytes are intentionally opaque raw content, as upstream's
// program.db calls are.
//
// Apply and FixedBackend remain available for callers that already own a
// semantic Program or require same-size replacement only.
//
// In the upstream export pipeline ised runs after intrinsic/hook rewriting,
// easy-PIC/DFR resolution, ordering/rule analysis, and +mutate; it runs before
// +regdance and the final +blockparty/+shatter jump-healing pass.
package ised
