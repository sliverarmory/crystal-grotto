/* SPDX-License-Identifier: GPL-3.0-only */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	movl $0xdb2d49b0, %ecx
	call __resolve_hook
	testq %rax, %rax
	je no_hook
	jmp *%rax
no_hook:
	xorl %eax, %eax
	ret

	.globl wrapper
	.def wrapper; .scl 2; .type 32; .endef
wrapper:
	movl $42, %eax
	ret
