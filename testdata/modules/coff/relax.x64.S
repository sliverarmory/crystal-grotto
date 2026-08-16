/* SPDX-License-Identifier: GPL-3.0-only */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	movq .refptr.target(%rip), %rax
	ret

	.globl target
	.def target; .scl 2; .type 32; .endef
target:
	ret

	.section .rdata$.refptr.target,"dr"
	.linkonce discard
	.globl .refptr.target
.refptr.target:
	.quad target
