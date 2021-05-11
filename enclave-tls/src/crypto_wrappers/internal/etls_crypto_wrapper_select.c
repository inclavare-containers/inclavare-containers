/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"

static enclave_tls_err_t init_crypto_wrapper(crypto_wrapper_ctx_t *crypto_ctx)
{
	enclave_tls_err_t err = crypto_ctx->opts->init(crypto_ctx);

	if (err != CRYPTO_WRAPPER_ERR_NONE)
		return err;

	if (!crypto_ctx->crypto_private)
		return -ENCLAVE_TLS_ERR_INIT;

	return ENCLAVE_TLS_ERR_NONE;
}

enclave_tls_err_t etls_crypto_wrapper_select(etls_core_context_t *ctx,
					     const char *type)
{
	ETLS_DEBUG("selecting the crypto wrapper '%s' ...\n", type);

	crypto_wrapper_ctx_t *crypto_ctx = NULL;
	unsigned int i = 0;
	for (; i < registerd_crypto_wrapper_nums; ++i) {
		crypto_ctx = crypto_wrappers_ctx[i];

		if (type && strcmp(type, crypto_ctx->opts->type))
			continue;

		crypto_wrapper_ctx_t *this_crypto_ctx = malloc(sizeof(*this_crypto_ctx));
		if (!this_crypto_ctx)
			return -ENCLAVE_TLS_ERR_NO_MEM;

		*this_crypto_ctx = *crypto_ctx;
		crypto_ctx = this_crypto_ctx;

		/* Set necessary configurations from enclave_tls_init() to
		 * make init() working correctly.
		 */
		crypto_ctx->enclave_id = ctx->config.enclave_id;
		crypto_ctx->conf_flags = ctx->config.flags;
		crypto_ctx->log_level = ctx->config.log_level;
		crypto_ctx->cert_algo = ctx->config.cert_algo;

		if (init_crypto_wrapper(crypto_ctx) == ENCLAVE_TLS_ERR_NONE)
			break;
	}

	if (i == registerd_crypto_wrapper_nums) {
		if (!type)
			ETLS_ERR("failed to select a crypto wrapper\n");
		else
			ETLS_ERR("failed to select the crypto wrapper '%s'\n", type);

		return -ENCLAVE_TLS_ERR_INIT;
	}

	ctx->crypto_wrapper = crypto_ctx;
	ctx->flags |= ENCLAVE_TLS_CTX_FLAGS_CRYPTO_INITIALIZED;

	ETLS_INFO("the crypto wrapper '%s' selected\n", crypto_ctx->opts->type);

	return ENCLAVE_TLS_ERR_NONE;
}
