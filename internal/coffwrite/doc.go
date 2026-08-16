// SPDX-License-Identifier: GPL-3.0-only
//
// Crystal Grotto is based on Crystal Palace.
// Copyright 2025 Raphael Mudge, Adversary Fan Fiction Writers Guild.
// See LICENSE.upstream.

// Package coffwrite serializes the in-memory Microsoft COFF model.
//
// Marshal preserves represented header, section, symbol, auxiliary-record, and
// relocation data while recomputing every file pointer and symbol-table index.
// Its physical ordering follows Crystal Palace's ProgramCOFF/FormatCOFF output:
// file and section headers, each section's relocations followed by its raw data,
// the symbol table, and finally the string table.
//
// The coff.Object model does not retain line-number table bytes, parsed label
// symbols in its public Symbols slice, or the original spelling of normalized
// label names. Marshal rejects nonzero line-number metadata. A parse/marshal
// cycle cannot reproduce label records that were retained only in coff's
// private raw-symbol index. Parsed Section.Alignment is also not recoverable;
// coff.Parse currently initializes it to one, although the raw Characteristics
// alignment bits and section pointers remain represented.
package coffwrite
