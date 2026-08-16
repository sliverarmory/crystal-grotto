// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

// Package shatter implements Crystal Palace's program-wide +shatter basic
// block pass. The first block of every function stays at that function's
// symbol. All remaining blocks are shuffled together and distributed across
// those function homes in the Java HashMap order used by upstream.
//
// Apply is deliberately not idempotent. Crystal Palace likewise documents a
// shattered COFF as safe for direct execution but unsupported as input to a
// later transforming pass because its function boundaries no longer describe
// logical functions.
//
// Heal exposes the same final rebuild without a structural filter. Crystal
// Palace runs that form after ISED or other BTF work even when neither
// +shatter nor +blockparty is selected, notably to remove +split's EB 00
// markers. If both structural options are requested, upstream chooses
// +shatter and does not run +blockparty.
package shatter
