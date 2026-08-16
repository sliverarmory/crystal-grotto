/* SPDX-License-Identifier: GPL-3.0-only
 * Original Crystal Grotto upstream-compatibility fixture.
 */

	.text
	.globl _go
	.def _go; .scl 2; .type 32; .endef
_go:
	call _helper
	ret

	.globl _dead_one
	.def _dead_one; .scl 2; .type 32; .endef
_dead_one:
	movl $1, %eax
	ret

	.globl _helper
	.def _helper; .scl 2; .type 32; .endef
_helper:
	movl $42, %eax
	ret

	.globl _dead_two
	.def _dead_two; .scl 2; .type 32; .endef
_dead_two:
	movl $2, %eax
	ret
