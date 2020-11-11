/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/*
 * Copyright(c) 2016-18 Intel Corporation.
 */

#include "sgx_call.h"

	.section ".tcs", "a"
	.balign	4096

	.fill	1, 8, 0			# STATE (set by CPU)
	.fill	1, 8, 0			# FLAGS
	.quad	0			# OSSA (set by skeleton)
	.fill	1, 4, 0			# CSSA (set by CPU)
	.fill	1, 4, 1			# NSSA
	.quad	encl_entry		# OENTRY
	.fill	1, 8, 0			# AEP (set by EENTER and ERESUME)
	.fill	1, 8, 0			# OFSBASE
	.fill	1, 8, 0			# OGSBASE
	.fill	1, 4, 0xFFFFFFFF 	# FSLIMIT
	.fill	1, 4, 0xFFFFFFFF	# GSLIMIT
	.fill	4024, 1, 0		# Reserved

	.text

	# At this moment, the register context is:
	# - R10: the ecall number
	# - RDI, RSI, RDX, R8 and R9: function parameters
	# - R11: the backup of fouth parameter originated from RCX
	# - RAX: the CSSA of current TCS
	# - RBX: the base of TCS page
	# - RCX: the return address after EENTER
encl_entry:
	cmp	$MAX_ECALLS, %r10
	jge	err

	# RBX contains the base address for TCS, which is also the first address
	# inside the enclave. By adding the value of le_stack_end to it, we get
	# the absolute address for the stack.
	lea	(encl_stack)(%rbx), %r12
	xchg	%rsp, %r12

	# Save the return address after EENTER to be consumed by EEXIT.
	mov	%rcx, %r13

	# Recover the fouth parameter.
	mov	%r11, %rcx

	# Call ecall function according to R10.
	lea	enclave_call_table(%rip), %r14
	mov	(%r14, %r10, 8), %r14
	call	1f
1:
	pop	%r15
	sub	$1b, %r15
	add	%r15, %r14
	call	*%r14

	# Return the result of ecall function in RDX.
	mov	%rax, %rdx

	# Restore XSAVE registers to a synthetic state.
	lea	(xsave_area)(%rbx), %rdi
	fxrstor	(%rdi)

	# Prepare EEXIT target after EENTER.
	mov	%r13, %rbx

	# Restore the caller stack.
	mov	%r12, %rsp

	# Clear GPRs.
	xor     %rbp, %rbp
	xor     %rdi, %rdi
	xor     %rsi, %rsi
	xor     %r8, %r8
	xor     %r9, %r9
	xor     %r10, %r10
	xor     %r11, %r11
	xor     %r12, %r12
	xor     %r13, %r13
	xor     %r14, %r14
	xor     %r15, %r15

	# Reset status flags.
	add     %r15, %r15 # OF = SF = AF = CF = 0; ZF = PF = 1

2:
	# EEXIT ABI:
	# - [IN] RAX contains the EEXIT leaf number 4
	# - [IN] RBX points to the return address of EEXIT
	mov	$EEXIT, %rax
	ENCLU
	# Never return
3:	jmp	3b
err:
	mov	%rcx, %rbx
	jmp	2b

	.section ".data", "aw"

xsave_area:
	.fill	1, 4, 0x037F		# FCW
	.fill	5, 4, 0
	.fill	1, 4, 0x1F80		# MXCSR
	.fill	1, 4, 0xFFFF		# MXCSR_MASK
	.fill	123, 4, 0
	.fill	1, 4, 0x80000000	# XCOMP_BV[63] = 1, compaction mode
	.fill	12, 4, 0

	.balign 4096
	.space 8192
encl_stack:
