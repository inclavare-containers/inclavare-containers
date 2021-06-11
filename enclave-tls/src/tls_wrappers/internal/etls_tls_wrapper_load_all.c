/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdlib.h>
#ifndef SGX
#include<sys/types.h>
#include <dirent.h>
#endif
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/tls_wrapper.h"

// clang-format off
#ifdef OCCLUM
  #define PATTERN_SUFFIX ".so"
#endif
// clang-format on
#ifdef SGX
#include <sgx_error.h>
#include "etls_t.h"
#define DT_REG 8
#endif

static int tls_wrapper_cmp(const void *a, const void *b)
{
	return (*(tls_wrapper_ctx_t **)b)->opts->priority -
	       (*(tls_wrapper_ctx_t **)a)->opts->priority;
}

enclave_tls_err_t etls_tls_wrapper_load_all(void)
{
	ETLS_DEBUG("called\n");

#ifdef SGX
	uint64_t dir = 0;
	int sgx_status = 0;
	sgx_status = ocall_opendir(&dir, TLS_WRAPPERS_DIR);
	if (sgx_status != SGX_SUCCESS || !dir) {
		ETLS_ERR("failed to open %s, %#x, %#x", TLS_WRAPPERS_DIR, sgx_status, dir);
		return -ENCLAVE_TLS_ERR_UNKNOWN;
	}
#else
	DIR *dir = opendir(TLS_WRAPPERS_DIR);
	if (!dir) {
		ETLS_ERR("failed to open %s", TLS_WRAPPERS_DIR);
		return -ENCLAVE_TLS_ERR_UNKNOWN;
	}
#endif

	unsigned int total_loaded = 0;
#ifdef SGX
	int ret = 0;
	struct etls_dirent *ptr;
	ptr = (struct etls_dirent *)calloc(1, sizeof(struct etls_dirent));
	ocall_readdir(&ret, dir, ptr);
	while (ptr != NULL) {
#else 
	struct dirent *ptr;
	while ((ptr = readdir(dir)) != NULL) {
#endif
		if (!strcmp(ptr->d_name, ".") || !strcmp(ptr->d_name, ".."))
			continue;

#ifdef OCCLUM
		/* Occlum can't identify the d_type of the file, always return DT_UNKNOWN */
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)) == 0) {
#else
		if (ptr->d_type == DT_REG) {
#endif
			if (etls_tls_wrapper_load_single(ptr->d_name) == ENCLAVE_TLS_ERR_NONE)
				++total_loaded;
		}
#ifdef SGX
		ocall_readdir(&ret, dir, ptr);
#endif
	}

#ifdef SGX
	ocall_closedir(&ret, dir);
#else
	closedir(dir);
#endif

	if (!total_loaded) {
		ETLS_ERR("unavailable tls wrapper instance under %s\n", TLS_WRAPPERS_DIR);
		return -ENCLAVE_TLS_ERR_LOAD_TLS_WRAPPERS;
	}

	/* Sort all tls_wrappers_ctx_t instances in the tls_wrappers_ctx, and the higher priority
	 * instance should be sorted in front of the tls_wrappers_ctx array.
	 */
	qsort(tls_wrappers_ctx, tls_wrappers_nums, sizeof(tls_wrapper_ctx_t *), tls_wrapper_cmp);

	return ENCLAVE_TLS_ERR_NONE;
}
