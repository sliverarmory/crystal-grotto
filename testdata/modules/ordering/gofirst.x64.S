/* SPDX-License-Identifier: GPL-3.0-only
 * Original Crystal Grotto upstream-compatibility fixture.
 */

	.text
	.globl helper
	.def helper; .scl 2; .type 32; .endef
helper:
	movl $42, %eax
	ret
	nop
	int3

	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	/* Moving this function ahead of helper changes the resolved rel32. */
	call helper
	ret
	nop
	int3

	.globl tail
	.def tail; .scl 2; .type 32; .endef
tail:
	movl $7, %eax
	ret
	nop
	int3
