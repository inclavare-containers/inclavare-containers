// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#include <stddef.h>
#include "defines.h"
#include "arch.h"
#include "sgx_call.h"

static void *memcpy(void *dest, const void *src, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		((char *)dest)[i] = ((char *)src)[i];

	return dest;
}

static int encl_init(void *dst)
{
	static uint64_t magic = INIT_MAGIC;

	memcpy(dst, &magic, 8);

	return 0;
}

unsigned long enclave_call_table[MAX_ECALLS] = {
        (unsigned long)encl_init,
};
