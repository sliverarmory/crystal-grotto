/* SPDX-License-Identifier: GPL-3.0-only */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	pushq %rbp
	pushq %rbx
	subq $0x20, %rsp
	movq %rsp, %rbp
	leaq unwind_resource(%rip), %rax
	call helper
	addq $0x20, %rsp
	popq %rbx
	popq %rbp
	ret

	.globl helper
	.def helper; .scl 2; .type 32; .endef
helper:
	pushq %rbp
	movq %rsp, %rbp
	popq %rbp
	ret

	/* Bound helper before the assembler's trailing .text padding. */
	.globl helper_end
	.def helper_end; .scl 2; .type 0; .endef
helper_end:
