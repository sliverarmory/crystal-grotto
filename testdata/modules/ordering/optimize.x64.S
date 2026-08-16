/* SPDX-License-Identifier: GPL-3.0-only
 * Original Crystal Grotto upstream-compatibility fixture.
 */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	/* The ordinary same-section call has a COFF REL32 relocation until link
	 * merge.  The ordering pass must still discover and repair it afterward. */
	call helper
	ret
	nop
	int3

	.globl dead
	.def dead; .scl 2; .type 32; .endef
dead:
	movl $7, %eax
	ret
	nop
	int3

	.globl helper
	.def helper; .scl 2; .type 32; .endef
helper:
	movl $42, %eax
	ret
	nop
	int3
