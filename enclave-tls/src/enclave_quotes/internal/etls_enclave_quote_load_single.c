/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/core.h"
#include "internal/enclave_quote.h"

#define PATTERN_PREFIX "libenclave_quote_"
#ifdef SGX
#define PATTERN_SUFFIX          ".a"
#else
#define PATTERN_SUFFIX ".so"
#endif

enclave_tls_err_t etls_enclave_quote_load_single(const char *fname)
{
	ETLS_DEBUG("loading the enclave quote instance '%s' ...\n", fname);

	/* Check whether the filename pattern matches up libenclave_quote_<name>.so */
	if (strlen(fname) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(fname, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(fname + strlen(fname) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX,
		    strlen(PATTERN_SUFFIX))) {
		ETLS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX
			 "<name>" PATTERN_SUFFIX "\n",
			 fname);
		return -ENCLAVE_TLS_ERR_INVALID;
	}

	char realpath[strlen(ENCLAVE_QUOTES_DIR) + strlen(fname) + 1];
	snprintf(realpath, sizeof(realpath), "%s%s", ENCLAVE_QUOTES_DIR, fname);

	size_t name_len = strlen(fname) - strlen(PATTERN_PREFIX) - strlen(PATTERN_SUFFIX);
	char name[name_len + 1];
	strncpy(name, fname + strlen(PATTERN_PREFIX), name_len);
	name[name_len] = '\0';

	void *handle = NULL;
	enclave_tls_err_t err = etls_instance_init(name, realpath, &handle);
	if (err != ENCLAVE_TLS_ERR_NONE)
		return err;

	unsigned int i = 0;
	enclave_quote_opts_t *opts = NULL;
	for (i = 0; i < registerd_enclave_quote_nums; ++i) {
		opts = enclave_quotes_opts[i];

		if (!strcmp(name, opts->name))
			break;
	}

	if (i == registerd_enclave_quote_nums) {
		ETLS_DEBUG("the enclave quote '%s' failed to register\n", name);
		return -ENCLAVE_TLS_ERR_NOT_REGISTERED;
	}

	if (opts->pre_init) {
		enclave_tls_err_t err = opts->pre_init();

		if (err != ENCLAVE_QUOTE_ERR_NONE) {
			ETLS_ERR("failed on pre_init() of enclave quote '%s' %#x\n", name, err);
			return err;
		}
	}

	enclave_quote_ctx_t *quote_ctx = calloc(1, sizeof(*quote_ctx));
	if (!quote_ctx)
		return -ENCLAVE_TLS_ERR_NO_MEM;

	quote_ctx->opts = opts;
	quote_ctx->log_level = global_core_context.config.log_level;
	quote_ctx->handle = handle;

	enclave_quotes_ctx[enclave_quote_nums++] = quote_ctx;

	ETLS_DEBUG("the enclave quote '%s' loaded\n", name);

	return ENCLAVE_TLS_ERR_NONE;
}
