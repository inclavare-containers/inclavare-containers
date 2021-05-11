/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/enclave_quote.h"
#include "internal/core.h"

static enclave_tls_err_t init_enclave_quote(etls_core_context_t *ctx,
					    enclave_quote_ctx_t *quote_ctx,
					    enclave_tls_cert_algo_t algo)
{
	enclave_tls_err_t err = quote_ctx->opts->init(quote_ctx, algo);

	if (err != ENCLAVE_QUOTE_ERR_NONE)
		return err;

	if (!quote_ctx->quote_private)
		return -ENCLAVE_TLS_ERR_INIT;

	return ENCLAVE_TLS_ERR_NONE;
}

enclave_tls_err_t etls_enclave_quote_select(etls_core_context_t *ctx,
					    const char *type,
					    enclave_tls_cert_algo_t algo)
{
	ETLS_DEBUG("selecting the enclave quote '%s' ...\n", type);

	enclave_quote_ctx_t *quote_ctx = NULL;
	unsigned int i = 0;
	for (; i < registerd_enclave_quote_nums; ++i) {
		quote_ctx = enclave_quotes_ctx[i];

		if (type && strcmp(type, quote_ctx->opts->type))
			continue;
	
		enclave_quote_ctx_t *this_quote_ctx = malloc(sizeof(*this_quote_ctx));
		if (!this_quote_ctx)
			 return -ENCLAVE_TLS_ERR_NO_MEM;
		
		memcpy(this_quote_ctx, quote_ctx, sizeof(*this_quote_ctx));
		quote_ctx = this_quote_ctx;

		/* Set necessary configurations from enclave_tls_init() to
		 * make init() working correctly.
		 */
		quote_ctx->enclave_id = ctx->config.enclave_id;
		quote_ctx->log_level = ctx->config.log_level;

		if (init_enclave_quote(ctx, quote_ctx, algo) == ENCLAVE_TLS_ERR_NONE)
			break;
	}

	if (i == registerd_enclave_quote_nums) {
		if (!type)
			ETLS_ERR("failed to select an enclave quote\n");
		else
			ETLS_ERR("failed to select the enclave quote '%s'\n", type);

		return -ENCLAVE_TLS_ERR_INVALID;
	}

	ctx->attester = ctx->verifier = quote_ctx;
	ctx->flags |= ENCLAVE_TLS_CTX_FLAGS_QUOTING_INITIALIZED;

	ETLS_INFO("the enclave quote '%s' selected\n", ctx->attester->opts->type);

	return ENCLAVE_TLS_ERR_NONE;
}
