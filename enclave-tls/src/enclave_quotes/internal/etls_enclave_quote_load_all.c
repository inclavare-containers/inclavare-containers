/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/enclave_quote.h"

// clang-format off
#ifdef OCCLUM
  #define PATTERN_SUFFIX ".so"
#endif
// clang-format on

static int enclave_quote_cmp(const void *a, const void *b)
{
	return (*(enclave_quote_ctx_t **)b)->opts->priority -
	       (*(enclave_quote_ctx_t **)a)->opts->priority;
}

enclave_tls_err_t etls_enclave_quote_load_all(void)
{
	ETLS_DEBUG("called\n");

	DIR *dir = opendir(ENCLAVE_QUOTES_DIR);
	if (!dir) {
		ETLS_ERR("failed to open %s", ENCLAVE_QUOTES_DIR);
		return -ENCLAVE_TLS_ERR_UNKNOWN;
	}

	unsigned int total_loaded = 0;
	struct dirent *ptr;
	while ((ptr = readdir(dir)) != NULL) {
		if (!strcmp(ptr->d_name, ".") || !strcmp(ptr->d_name, ".."))
			continue;

#ifdef OCCLUM
		/* Occlum can't identify the d_type of the file, always return DT_UNKNOWN */
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)) == 0) {
#else
		if (ptr->d_type == DT_REG) {
#endif
			if (etls_enclave_quote_load_single(ptr->d_name) == ENCLAVE_TLS_ERR_NONE)
				++total_loaded;
		}
	}

	closedir(dir);

	if (!total_loaded) {
		ETLS_ERR("unavailable enclave quote instance under %s\n", ENCLAVE_QUOTES_DIR);
		return -ENCLAVE_TLS_ERR_LOAD_ENCLAVE_QUOTES;
	}

	/* Sort all enclave_quote_ctx_t instances in the enclave_quotes_ctx, and the higher priority
	 * instance should be sorted in front of the enclave_quotes_ctx array.
	 */
	qsort(enclave_quotes_ctx, enclave_quote_nums, sizeof(enclave_quote_ctx_t *),
	      enclave_quote_cmp);

	return ENCLAVE_TLS_ERR_NONE;
}
