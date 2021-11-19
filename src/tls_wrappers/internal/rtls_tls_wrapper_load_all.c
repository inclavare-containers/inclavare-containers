/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <string.h>
#include <stdlib.h>
#ifndef SGX
#include <sys/types.h>
#include <dirent.h>
#endif
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/tls_wrapper.h"
#define PATTERN_SUFFIX ".so"
#ifdef SGX
#include <sgx_error.h>
#include "rtls_t.h"
#define DT_REG 8
#define DT_LNK 10
#endif
// clang-format on

static int tls_wrapper_cmp(const void *a, const void *b)
{
	return (*(tls_wrapper_ctx_t **)b)->opts->priority -
	       (*(tls_wrapper_ctx_t **)a)->opts->priority;
}

rats_tls_err_t rtls_tls_wrapper_load_all(void)
{
	RTLS_DEBUG("called\n");

	uint64_t dir = rtls_opendir(TLS_WRAPPERS_DIR);
	if (!dir) {
		RTLS_ERR("failed to open %s\n", TLS_WRAPPERS_DIR);
		return -RATS_TLS_ERR_UNKNOWN;
	}

	unsigned int total_loaded = 0;
	rtls_dirent *ptr;
	while (rtls_readdir(dir, &ptr) != 1) {
		if (!strcmp(ptr->d_name, ".") || !strcmp(ptr->d_name, "..")) {
			continue;
		}
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX))) {
			continue;
		}

#ifdef OCCLUM
		/* Occlum can't identify the d_type of the file, always return DT_UNKNOWN */
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)) == 0) {
#else
		if (ptr->d_type == DT_REG || ptr->d_type == DT_LNK) {
#endif
			if (rtls_tls_wrapper_load_single(ptr->d_name) == RATS_TLS_ERR_NONE)
				++total_loaded;
		}
	}

	rtls_closedir((uint64_t)dir);

	if (!total_loaded) {
		RTLS_ERR("unavailable tls wrapper instance under %s\n", TLS_WRAPPERS_DIR);
		return -RATS_TLS_ERR_LOAD_TLS_WRAPPERS;
	}

	/* Sort all tls_wrappers_ctx_t instances in the tls_wrappers_ctx, and the higher priority
	 * instance should be sorted in front of the tls_wrappers_ctx array.
	 */
	qsort(tls_wrappers_ctx, tls_wrappers_nums, sizeof(tls_wrapper_ctx_t *), tls_wrapper_cmp);

	return RATS_TLS_ERR_NONE;
}
