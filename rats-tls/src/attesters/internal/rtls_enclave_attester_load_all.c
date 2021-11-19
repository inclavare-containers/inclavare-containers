/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <string.h>
#include <stdlib.h>
#ifndef SGX
#include <dirent.h>
#endif
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/attester.h"
#define PATTERN_SUFFIX ".so"
#ifdef SGX
#include <sgx_error.h>
#include "rtls_t.h"
#define DT_REG 8
#define DT_LNK 10
#endif
// clang-format on

static int enclave_attester_cmp(const void *a, const void *b)
{
	return (*(enclave_attester_ctx_t **)b)->opts->priority -
	       (*(enclave_attester_ctx_t **)a)->opts->priority;
}

rats_tls_err_t rtls_enclave_attester_load_all(void)
{
	RTLS_DEBUG("called\n");

	uint64_t dir = rtls_opendir(ENCLAVE_ATTESTERS_DIR);
	if (!dir) {
		RTLS_ERR("failed to open %s", ENCLAVE_ATTESTERS_DIR);
		return -RATS_TLS_ERR_UNKNOWN;
	}

	unsigned int total_loaded = 0;
	rtls_dirent *ptr;
	while ((rtls_readdir(dir, &ptr)) != 1) {
		if (!strcmp(ptr->d_name, ".") || !strcmp(ptr->d_name, ".."))
			continue;
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)))
			continue;

#ifdef OCCLUM
		/* Occlum can't identify the d_type of the file, always return DT_UNKNOWN */
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)) == 0) {
#else
		if (ptr->d_type == DT_REG || ptr->d_type == DT_LNK) {
#endif
			if (rtls_enclave_attester_load_single(ptr->d_name) == RATS_TLS_ERR_NONE)
				++total_loaded;
		}
	}

	rtls_closedir(dir);

	if (!total_loaded) {
		RTLS_ERR("unavailable enclave attester instance under %s\n", ENCLAVE_ATTESTERS_DIR);
		return -RATS_TLS_ERR_LOAD_ENCLAVE_ATTESTERS;
	}

	/* Sort all enclave_attester_ctx_t instances in the enclave_attesters_ctx, and the higher priority
	 * instance should be sorted in front of the enclave_attesters_ctx array.
	 */
	qsort(enclave_attesters_ctx, enclave_attester_nums, sizeof(enclave_attester_ctx_t *),
	      enclave_attester_cmp);

	return RATS_TLS_ERR_NONE;
}
