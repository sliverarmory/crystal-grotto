/* SPDX-License-Identifier: GPL-3.0-only */

	.text
	.globl _go
	.def _go; .scl 2; .type 32; .endef
_go:
	movl $42, %eax
	ret

	.section .rdata,"dr"
	.byte 0x11, 0x22, 0x33, 0x44
