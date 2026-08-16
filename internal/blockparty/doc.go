// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

// Package blockparty implements Crystal Palace's +blockparty basic-block
// permutation pass.
//
// The upstream implementation preserves the first block of each function and
// shuffles every remaining block. Its comment says that the last block is also
// preserved, but the implementation includes that block in Collections.shuffle;
// this package deliberately follows the observable implementation.
package blockparty
