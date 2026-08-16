/* SPDX-License-Identifier: GPL-3.0-only
 * Original Crystal Grotto upstream-compatibility fixture.
 */

	.text
	.globl _go
	.def _go; .scl 2; .type 32; .endef
_go:
	/* The ordinary same-section call has a COFF REL32 relocation until link
	 * merge.  The ordering pass must still discover and repair it afterward. */
	call _helper
	ret
	nop
	int3

	.globl _dead
	.def _dead; .scl 2; .type 32; .endef
_dead:
	movl $7, %eax
	ret
	nop
	int3

	.globl _helper
	.def _helper; .scl 2; .type 32; .endef
_helper:
	movl $42, %eax
	ret
	nop
	int3
