/* SPDX-License-Identifier: GPL-3.0-only */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	.byte 0xeb, 0x0f
	movl $0x04030201, %eax
	addl $0x11223344, %eax
	call helper

.Lfinal:
	xorl %eax, %eax
	ret

	.globl helper
	.def helper; .scl 2; .type 32; .endef
helper:
	ret
