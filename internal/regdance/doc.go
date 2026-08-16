// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

// Package regdance implements Crystal Palace's +regdance nonvolatile-register
// permutation pass for Microsoft x86 and x64 COFF objects. It belongs after
// +mutate and ised rewrites and before +blockparty/+shatter in the BTF order.
//
// go-capstone v0.0.1 does not expose x86 operand detail. Legacy encodings are
// therefore rewritten only after Capstone verifies the complete substituted
// mnemonic and operand list. Eligible VEX/EVEX/XOP or otherwise ambiguous
// forms return UnsupportedInstructionError instead of being silently skipped.
package regdance
