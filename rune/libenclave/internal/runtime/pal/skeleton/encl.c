// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <stddef.h>
#include "defines.h"
#include "arch.h"
#include "sgx_call.h"

struct metadata m __attribute__((section(".metadata"))) = {
	.max_mmap_size = 0,
	.null_dereference_protection = false,
	.mmap_min_addr = 0
};

static void *memcpy(void *dest, const void *src, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		((char *) dest)[i] = ((char *) src)[i];

	return dest;
}

static int encl_init(void *dst)
{
	memcpy(dst, INIT_HELLO, sizeof(INIT_HELLO));

	return 0;
}

/* *INDENT-OFF* */
static int encl_get_report(const struct sgx_target_info *target_info,
			   const uint8_t *report_data,
			   struct sgx_report *report)
{
	struct sgx_target_info ti;
	memcpy(&ti, target_info, SGX_TARGET_INFO_SIZE);

	struct sgx_report_data rd;
	memcpy(&rd, report_data, SGX_REPORT_DATA_SIZE);

	struct sgx_report r;

	asm volatile(
		ENCLU "\n\t"
		:: "a" (EREPORT), "b" (&ti), "c" (&rd), "d" (&r)
		: "memory"
	);

	memcpy(report, &r, SGX_REPORT_SIZE);

	return 0;
}
/* *INDENT-ON* */

unsigned long enclave_call_table[MAX_ECALLS] = {
	(unsigned long) encl_init,
	(unsigned long) encl_get_report,
};
