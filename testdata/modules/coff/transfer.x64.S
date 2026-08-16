/* SPDX-License-Identifier: GPL-3.0-only */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	pushq %rbx
	subq $0x20, %rsp
	leaq target(%rip), %rcx
	call __transfer
	nop

	.globl target
	.def target; .scl 2; .type 32; .endef
target:
	movl $42, %eax
	ret
