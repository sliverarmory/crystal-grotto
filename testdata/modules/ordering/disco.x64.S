/* SPDX-License-Identifier: GPL-3.0-only
 * Original Crystal Grotto upstream-compatibility fixture.
 */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	call helper
	ret

	.globl dead_one
	.def dead_one; .scl 2; .type 32; .endef
dead_one:
	movl $1, %eax
	ret

	.globl helper
	.def helper; .scl 2; .type 32; .endef
helper:
	movl $42, %eax
	ret

	.globl dead_two
	.def dead_two; .scl 2; .type 32; .endef
dead_two:
	movl $2, %eax
	ret
