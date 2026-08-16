// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

// Package hooks models Crystal Palace hook, intrinsic, and exception-handler
// directives.
//
// Model values are immutable. Apply validates an entire directive and returns
// a new value, leaving the receiver unchanged on both success and failure.
// Queries are safe to call concurrently.
//
// This package resolves hook precedence and produces exact intrinsic
// replacement bytes, but it deliberately does not pretend to rebuild machine
// code. Attach and redirect can require rewriting several compiler-dependent
// x86 instruction forms; addhook's __resolve_hook expansion synthesizes a
// control-flow program; catch requires x64 unwind-table regeneration. Those
// consumers must use an architecture-aware encoder/rebuilder. HookPlan marks
// this requirement explicitly, and intrinsic Expansion reports when replacing
// a call changes its encoded length.
package hooks
