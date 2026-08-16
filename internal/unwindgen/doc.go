// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Portions translated from Crystal Palace, Copyright 2025 Raphael Mudge and
// the Adversary Fan Fiction Writers Guild, under the BSD-3-Clause license.

// Package unwindgen regenerates Windows x64 pdata/xdata after Crystal Grotto
// has finished instruction-changing transforms.
//
// The upstream export order is significant: normalize and transform code,
// generate pdata/xdata, run diagnostics, apply symbol patches, build linkpost
// unwind resources, add the PICO .cpl_unwind resource when requested, and only
// then perform the final export. Generate is pure, Apply installs freshly
// generated pdata/xdata transactionally, and BuildResource deliberately stays
// separate so a caller can run it after patches.
//
// Crystal Palace uses Iced architecture detail for prologue and stack-effect
// analysis. This package proves the compiler forms it emits directly from
// their x64 bytes and portable disassembly boundaries. A stack-affecting form
// whose semantics cannot be established is returned as ErrUnsupportedDetail;
// it is never assigned speculative unwind metadata.
package unwindgen
