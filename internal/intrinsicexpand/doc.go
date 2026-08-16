// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

// Package intrinsicexpand applies arbitrary-length user-defined linker
// intrinsics and the preceding named-hash/tag built-ins before the remaining
// hook encoders. It consumes canonical CALL relocations in one upstream-style
// rebuild and delegates layout repair to the conservative ISED object rebaser
// so symbols, relocations, branches, and supported metadata move as one
// transaction.
package intrinsicexpand
