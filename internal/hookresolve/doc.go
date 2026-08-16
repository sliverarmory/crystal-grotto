// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

// Package hookresolve expands Crystal Palace's __resolve_hook linker
// intrinsic. It preserves each original CALL site and emits a guarded code
// subsection containing context-specific resolver stubs. This is semantically
// compatible with the upstream inline expansion while keeping existing source
// offsets stable for later transforms.
package hookresolve
