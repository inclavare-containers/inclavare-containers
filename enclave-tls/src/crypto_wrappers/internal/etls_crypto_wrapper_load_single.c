/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"

// clang-format off
#define PATTERN_PREFIX "libcrypto_wrapper_"
#ifdef SGX
#define PATTERN_SUFFIX ".a"
#else
#define PATTERN_SUFFIX ".so"
#endif
//clang-format on

enclave_tls_err_t etls_enclave_crypto_post_init(const char *name, void *handle)
{
	unsigned int i = 0;
	crypto_wrapper_opts_t *opts = NULL;
	for (i = 0; i < registerd_crypto_wrapper_nums; ++i) {
		opts = crypto_wrappers_opts[i];

		if (!strcmp(name, opts->name))
			break;
	}

	if (i == registerd_crypto_wrapper_nums) {
		ETLS_DEBUG("the crypto wrapper '%s' failed to register\n", name);
		return -ENCLAVE_TLS_ERR_NOT_REGISTERED;
	}

	if (opts->pre_init) {
		crypto_wrapper_err_t err_cw = opts->pre_init();
		if (err_cw != CRYPTO_WRAPPER_ERR_NONE) {
			ETLS_ERR("failed on pre_init() of crypto wrapper '%s' %#x\n", name, err_cw);
			return -ENCLAVE_TLS_ERR_INVALID;
		}
	}

	crypto_wrapper_ctx_t *crypto_ctx = calloc(1, sizeof(*crypto_ctx));
	if (!crypto_ctx)
		return -ENCLAVE_TLS_ERR_NO_MEM;

	crypto_ctx->opts = opts;
	crypto_ctx->conf_flags = global_core_context.config.flags;
	crypto_ctx->log_level = global_core_context.config.log_level;
	crypto_ctx->cert_algo = global_core_context.config.cert_algo;
	crypto_ctx->handle = handle;

	crypto_wrappers_ctx[crypto_wrappers_nums++] = crypto_ctx;

        return ENCLAVE_TLS_ERR_NONE;
}

enclave_tls_err_t etls_crypto_wrapper_load_single(const char *fname)
{
	ETLS_DEBUG("loading the crypto wrapper instance '%s' ...\n", fname);

	/* Check whether the filename pattern matches up libcrypto_wrapper_<name>.so */
	if (strlen(fname) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(fname, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(fname + strlen(fname) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX,
		    strlen(PATTERN_SUFFIX))) {
		ETLS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX
			 "<name>" PATTERN_SUFFIX "\n",
			 fname);
		return -ENCLAVE_TLS_ERR_INVALID;
	}

	char realpath[strlen(CRYPTO_WRAPPERS_DIR) + strlen(fname) + 1];
	snprintf(realpath, sizeof(realpath), "%s%s", CRYPTO_WRAPPERS_DIR, fname);

	uint32_t name_len = (uint32_t)strlen(fname) - (uint32_t)strlen(PATTERN_PREFIX) -
			    (uint32_t)strlen(PATTERN_SUFFIX);
	char name[name_len + 1];
	snprintf(name, sizeof(name), "%s", fname + strlen(PATTERN_PREFIX));

	void *handle = NULL;
	enclave_tls_err_t err = etls_instance_init(name, realpath, &handle);
	if (err != ENCLAVE_TLS_ERR_NONE)
		return err;

        err = etls_enclave_crypto_post_init(name, handle);
	if (err != ENCLAVE_TLS_ERR_NONE)
		return err;

	ETLS_DEBUG("the crypto wrapper '%s' loaded\n", name);

	return ENCLAVE_TLS_ERR_NONE;
}
