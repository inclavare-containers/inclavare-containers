/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"

static rats_tls_err_t init_crypto_wrapper(crypto_wrapper_ctx_t *crypto_ctx)
{
	crypto_wrapper_err_t err = crypto_ctx->opts->init(crypto_ctx);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		return err;

	if (!crypto_ctx->crypto_private)
		return -RATS_TLS_ERR_INIT;

	return RATS_TLS_ERR_NONE;
}

rats_tls_err_t rtls_crypto_wrapper_select(rtls_core_context_t *ctx, const char *name)
{
	RTLS_DEBUG("selecting the crypto wrapper '%s' ...\n", name);

	crypto_wrapper_ctx_t *crypto_ctx = NULL;
	for (unsigned int i = 0; i < registerd_crypto_wrapper_nums; ++i) {
		if (name && strcmp(name, crypto_wrappers_ctx[i]->opts->name))
			continue;

		crypto_ctx = malloc(sizeof(*crypto_ctx));
		if (!crypto_ctx)
			return -RATS_TLS_ERR_NO_MEM;

		*crypto_ctx = *crypto_wrappers_ctx[i];

		/* Set necessary configurations from rats_tls_init() to
		 * make init() working correctly.
		 */
		crypto_ctx->enclave_id = ctx->config.enclave_id;
		crypto_ctx->conf_flags = ctx->config.flags;
		crypto_ctx->log_level = ctx->config.log_level;
		crypto_ctx->cert_algo = ctx->config.cert_algo;

		if (init_crypto_wrapper(crypto_ctx) == RATS_TLS_ERR_NONE)
			break;

		free(crypto_ctx);
		crypto_ctx = NULL;
	}

	if (!crypto_ctx) {
		if (!name)
			RTLS_ERR("failed to select a crypto wrapper\n");
		else
			RTLS_ERR("failed to select the crypto wrapper '%s'\n", name);

		return -RATS_TLS_ERR_INIT;
	}

	ctx->crypto_wrapper = crypto_ctx;
	ctx->flags |= RATS_TLS_CTX_FLAGS_CRYPTO_INITIALIZED;

	RTLS_INFO("the crypto wrapper '%s' selected\n", crypto_ctx->opts->name);

	return RATS_TLS_ERR_NONE;
}
