// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

// Package rulegen generates conservative YARA signatures from Intel COFF
// objects. It is a deterministic port of Crystal Palace's rule-generation
// model and printer; candidates that need unavailable architecture-specific
// decoder detail are omitted with structured warnings.
package rulegen
