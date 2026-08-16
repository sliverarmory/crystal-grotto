/* SPDX-License-Identifier: GPL-3.0-only
 * Original Crystal Grotto upstream-compatibility fixture.
 */

	.text
	.globl _helper
	.def _helper; .scl 2; .type 32; .endef
_helper:
	movl $42, %eax
	ret
	nop
	int3

	.globl _go
	.def _go; .scl 2; .type 32; .endef
_go:
	/* Moving this function ahead of _helper changes the resolved rel32. */
	call _helper
	ret
	nop
	int3

	.globl _tail
	.def _tail; .scl 2; .type 32; .endef
_tail:
	movl $7, %eax
	ret
	nop
	int3
