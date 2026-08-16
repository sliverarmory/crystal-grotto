/* SPDX-License-Identifier: GPL-3.0-only */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	call *__imp_KERNEL32$Sleep(%rip)
	ret

	.globl resolve
	.def resolve; .scl 2; .type 32; .endef
resolve:
	cmpl $0x6a4abc5b, %ecx
	jne .Lbad
	cmpl $0xdb2d49b0, %edx
	jne .Lbad
	leaq resolved(%rip), %rax
	ret
.Lbad:
	leaq failed(%rip), %rax
	ret

	.globl resolved
	.def resolved; .scl 2; .type 32; .endef
resolved:
	movl $42, %eax
	ret

	.globl failed
	.def failed; .scl 2; .type 32; .endef
failed:
	movl $13, %eax
	ret

	.extern __imp_KERNEL32$Sleep
