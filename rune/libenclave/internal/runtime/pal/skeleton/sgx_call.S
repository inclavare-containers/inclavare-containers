/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
* Copyright(c) 2016-18 Intel Corporation.
*/

#include "sgx_call.h"

	.text

	# sgx ecall ABI:
	# - RDI, RSI, RDX, RCX, R8 and R9 are parameters
	# - R10 contains the ecall number
	# - R11 contains the base of TCS
	.global sgx_ecall
	.type sgx_ecall, @function
sgx_ecall:
	mov	$1, %rax
	push	%rbx
	mov	tcs_busy(%rip), %rbx	
	xchgb	(%rbx), %al
	cmpb	$1, %al
	jz	busy_err
	push	%rbp
	push	%rdi
	push	%rsi
	push    %r12
	push    %r13
	push    %r14
	push    %r15
	# EENTER ABI:
	# - [IN] RAX contains the EENTER leaf number 2
	# - [IN] RBX points to target TCS page
	# - [IN] RCX points to AEP
	mov	$0x02, %rax
	mov	%r11, %rbx
	# RCX is used to hold AEP so back up it with R11
	mov	%rcx, %r11
	lea	sgx_async_exit(%rip), %rcx
sgx_async_exit:
	ENCLU
	xor	%rax, %rax
	mov	tcs_busy(%rip), %rbx
	movb	%al, (%rbx)
	# Return value is saved in RAX.
	mov	%rdx, %rax
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rsi
	pop	%rdi
	pop	%rbp
busy_err:
	pop	%rbx
	ret
