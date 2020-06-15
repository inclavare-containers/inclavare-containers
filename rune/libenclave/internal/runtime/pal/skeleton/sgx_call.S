/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
* Copyright(c) 2016-18 Intel Corporation.
*/

	.text

	.macro ENCLU
	.byte 0x0f, 0x01, 0xd7
	.endm

	.text

	.global sgx_call_eenter
sgx_call_eenter:
	push	%rbx
	push	%rdi
	push	%rsi
	push    %r12
	push    %r13
	push    %r14
	push    %r15
	mov	$0x02, %rax
	mov	%rdx, %rbx
	lea	sgx_async_exit(%rip), %rcx
sgx_async_exit:
	ENCLU
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rsi
	pop	%rdi
	pop	%rbx
	ret
