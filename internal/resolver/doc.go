// SPDX-License-Identifier: GPL-3.0-only
// Derived from Crystal Palace, Copyright 2025 Raphael Mudge,
// Adversary Fan Fiction Writers Guild. See LICENSE.upstream.

// Package resolver models Crystal Palace dynamic function resolvers (DFR).
//
// The package parses COFF import spellings, validates and selects resolver
// directives, calculates resolver arguments, and identifies the canonical x86
// and x86-64 instruction forms accepted by the upstream ResolveAPI pass. Its
// built-in relocation-aware backend replaces those fixed-size forms with calls
// or jumps to deterministic resolver stubs without shifting existing code. It
// preserves ResolveAPI's calling contracts and register behavior but does not
// reproduce Iced's byte-for-byte inline expansion. A custom RewriteBackend
// remains available for callers that need a different instruction encoder.
package resolver
