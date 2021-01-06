/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2016-19 Intel Corporation.
 */
/* *INDENT-OFF* */
#ifndef SGX_CALL_H
#define SGX_CALL_H
/* *INDENT-ON* */

#define ECALL_INIT		0
#define ECALL_REPORT		1
#define MAX_ECALLS		2

#define EEXIT			4

#define INIT_HELLO		"Hello Inclavare Containers!"

/* *INDENT-OFF* */
#ifndef __ASSEMBLER__

#define SGX_ENTER_1_ARG(ecall_num, tcs, a0) \
	({      \
		int __ret; \
		asm volatile( \
			"mov %1, %%r10\n\t" \
			"mov %2, %%r11\n\t" \
			"call sgx_enclave_call\n\t" \
			: "=a" (__ret) \
			: "r" ((uint64_t)ecall_num), "r" (tcs), \
			  "D" (a0) \
			: "r10", "r11" \
		); \
		__ret; \
	})

#define SGX_ENTER_3_ARGS(ecall_num, tcs, a0, a1, a2) \
	({	\
		int __ret; \
		asm volatile( \
			"mov %1, %%r10\n\t" \
			"mov %2, %%r11\n\t" \
			"call sgx_enclave_call\n\t" \
			: "=a" (__ret) \
			: "r" ((uint64_t)ecall_num), "r" (tcs), \
			  "D" (a0), "S" (a1), "d" (a2) \
			: "r10", "r11" \
		); \
		__ret; \
	})

#define ENCLU			".byte 0x0f, 0x01, 0xd7"

#else

#define ENCLU			.byte 0x0f, 0x01, 0xd7

#endif

#endif /* SGX_CALL_H */
/* *INDENT-ON* */
