/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/core.h"
#include "internal/enclave_quote.h"

#define PATTERN_PREFIX          "libenclave_quote_"
#define PATTERN_SUFFIX          ".so"

enclave_tls_err_t etls_enclave_quote_load_single(const char *name)
{
	ETLS_DEBUG("loading the enclave quote instance '%s' ...\n", name);

	/* Check whether the filename pattern matches up libenclave_quote_<type>.so */
	if (strlen(name) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(name, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(name + strlen(name) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX, strlen(PATTERN_SUFFIX))) {
		ETLS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX "<type>" PATTERN_SUFFIX "\n",
			 name);
		return -ENCLAVE_TLS_ERR_INVALID;
	}

	char realpath[strlen(ENCLAVE_QUOTES_DIR) + strlen(name) + 1];
	sprintf(realpath, "%s%s", ENCLAVE_QUOTES_DIR, name);

	void *handle = dlopen(realpath, RTLD_LAZY);
	if (!handle) {
		ETLS_ERR("failed on dlopen(): %s\n", dlerror());
		return -ENCLAVE_TLS_ERR_DLOPEN;
	}

	size_t type_len = strlen(name) - strlen(PATTERN_PREFIX) - strlen(PATTERN_SUFFIX);
	char type[type_len + 1];
	strncpy(type, name + strlen(PATTERN_PREFIX), type_len);
	type[type_len] = '\0';

	unsigned int i = 0;
	enclave_quote_opts_t *opts = NULL;
	for (i = 0; i < registerd_enclave_quote_nums; ++i) {
		opts = enclave_quotes_opts[i];

		if (!strcmp(type, opts->type))
			break;
	}

	if (i == registerd_enclave_quote_nums) {
		ETLS_ERR("the enclave quote '%s' is not registered yet\n", type);
		return -ENCLAVE_TLS_ERR_NOT_REGISTERED;
	}

	if (opts->pre_init) {
		enclave_tls_err_t err = opts->pre_init();

		if (err != ENCLAVE_QUOTE_ERR_NONE) {
			ETLS_ERR("failed on pre_init() of enclave quote '%s' %#x\n", type, err);
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

	ETLS_DEBUG("the enclave quote '%s' loaded\n", type);

	return ENCLAVE_TLS_ERR_NONE;
}
