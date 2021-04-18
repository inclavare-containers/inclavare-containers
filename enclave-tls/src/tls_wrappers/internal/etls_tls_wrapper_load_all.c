/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/tls_wrapper.h"

#ifdef OCCLUM
  #define PATTERN_SUFFIX          ".so"
#endif

static int tls_wrapper_cmp(const void *a, const void *b)
{
	return (*(tls_wrapper_ctx_t **)b)->opts->priority -
		(*(tls_wrapper_ctx_t **)a)->opts->priority;
}

enclave_tls_err_t etls_tls_wrapper_load_all(void)
{
	ETLS_DEBUG("called\n");

	DIR *dir = opendir(TLS_WRAPPERS_DIR);
	if (!dir) {
		ETLS_ERR("failed to open %s", TLS_WRAPPERS_DIR);
		return -ENCLAVE_TLS_ERR_UNKNOWN;
	}

	unsigned int total_loaded = 0;
	struct dirent *ptr;
	while ((ptr = readdir(dir)) != NULL) {
		if (!strcmp(ptr->d_name, ".") ||
		    !strcmp(ptr->d_name, ".."))
			continue;

#ifdef OCCLUM
		/* Occlum can't identify the d_type of the file, always return DT_UNKNOWN */
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)) == 0) {
#else
			if (ptr->d_type == DT_REG) {
#endif
			if (etls_tls_wrapper_load_single(ptr->d_name) == ENCLAVE_TLS_ERR_NONE)
				++total_loaded;
		}
	}

	closedir(dir);

	if (!total_loaded) {
		ETLS_ERR("unavailable tls wrapper instance under %s\n",
			 TLS_WRAPPERS_DIR);
		return -ENCLAVE_TLS_ERR_LOAD_TLS_WRAPPERS;
	}

	/* Sort all tls_wrappers_ctx_t instances in the tls_wrappers_ctx, and the higher priority
	 * instance should be sorted in front of the tls_wrappers_ctx array.
	 */
	qsort(tls_wrappers_ctx, tls_wrappers_nums, sizeof(tls_wrapper_ctx_t *),
	      tls_wrapper_cmp);

	return ENCLAVE_TLS_ERR_NONE;
}
