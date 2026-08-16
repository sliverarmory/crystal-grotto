/* SPDX-License-Identifier: GPL-3.0-only */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	pushq %rbx
	popq %rbx
	movl $42, %eax
	ret
