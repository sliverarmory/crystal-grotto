/* SPDX-License-Identifier: GPL-3.0-only */

	.text
	.globl go
	.def go; .scl 2; .type 32; .endef
go:
	/* Save enough nonvolatile registers to make this function eligible for
	 * +regdance while remaining safe to call from the host PIC runner. */
	pushq %rbp
	pushq %rbx
	pushq %rsi
	pushq %rdi
	pushq %r12
	pushq %r13

	/* These constants are deliberately large enough for +mutate.  The
	 * register-dependent arithmetic also exercises a +regdance rewrite. */
	movl $0x11223344, %ebx
	movl $0x1122336e, %esi
	movl %esi, %eax
	subl %ebx, %eax

	/* Multiple local blocks give +blockparty and +shatter useful work while
	 * preserving a deterministic observable result. */
	cmpl $42, %eax
	jne .Lbad
	call helper
	jmp .Ldone
.Lbad:
	movl $13, %eax
.Ldone:
	popq %r13
	popq %r12
	popq %rdi
	popq %rsi
	popq %rbx
	popq %rbp
	ret

	.globl helper
	.def helper; .scl 2; .type 32; .endef
helper:
	/* A second function lets +shatter move blocks across function regions. */
	movl $42, %eax
	testl %eax, %eax
	je .Lhelper_bad
	ret
.Lhelper_bad:
	movl $13, %eax
	ret
