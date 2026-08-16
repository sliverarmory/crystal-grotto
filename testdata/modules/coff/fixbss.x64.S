/* SPDX-License-Identifier: GPL-3.0-only */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	movq .bss(%rip), %rax
	ret

	.globl getbss
	.def getbss; .scl 2; .type 32; .endef
getbss:
	ret

	.bss
	.p2align 3
	.space 32
