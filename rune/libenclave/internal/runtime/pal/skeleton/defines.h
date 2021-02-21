/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2016-19 Intel Corporation.
 */
/* *INDENT-OFF* */
#ifndef DEFINES_H
#define DEFINES_H
/* *INDENT-ON* */

#include <stdint.h>
#include <stdbool.h>

#define __aligned(x) __attribute__((__aligned__(x)))
#define __packed __attribute__((packed))
#define static_assert _Static_assert

struct metadata {
	uint64_t max_mmap_size;
	bool null_dereference_protection;
	uint64_t mmap_min_addr;
} __packed;

/* *INDENT-OFF* */
int get_mmap_min_addr(uint64_t *addr);
/* *INDENT-ON* */
uint64_t calc_enclave_offset(uint64_t mmap_min_addr,
			     bool null_dereference_protection);
bool is_legacy_oot_kernel_driver(void);
bool is_dcap_oot_kernel_driver(void);
bool is_in_tree_kernel_driver(void);

#include "arch.h"
#include "sgx.h"

#define ENCLAVE_GUARD_AREA_SIZE		(16 * 1024 * 1024)

#define pow2(sz) \
	({ \
		uint64_t __tmp; \
		for (__tmp = PAGE_SIZE; __tmp < (sz);) \
			__tmp <<= 1; \
		__tmp; \
	})

#define align_up(sz, a) \
	({ \
		(((sz) + (a) - 1) & ~((a) - 1)); \
	})

/* *INDENT-OFF* */
#endif /* DEFINES_H */
/* *INDENT-ON* */
