/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/attester.h"
#include "internal/core.h"

static rats_tls_err_t init_enclave_attester(rtls_core_context_t *ctx,
					       enclave_attester_ctx_t *attester_ctx,
					       rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("called enclave core ctx: %#x enclave attester ctx: %#x algo: %#x\n", ctx, attester_ctx, algo);

	enclave_attester_err_t err = attester_ctx->opts->init(attester_ctx, algo);
	if (err != ENCLAVE_ATTESTER_ERR_NONE)
		return -RATS_TLS_ERR_INIT;

	if (!attester_ctx->attester_private)
		return -RATS_TLS_ERR_INIT;

	return RATS_TLS_ERR_NONE;
}

rats_tls_err_t rtls_attester_select(rtls_core_context_t *ctx, const char *name,
				       rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("selecting the enclave attester '%s' cert algo '%#x'...\n", name, algo);

	/* Explicitly specify the enclave attester which will never be changed */
	if (name)
		ctx->flags |= RATS_TLS_CONF_FLAGS_ATTESTER_ENFORCED;

	enclave_attester_ctx_t *attester_ctx = NULL;
	for (unsigned int i = 0; i < registerd_enclave_attester_nums; ++i) {
		if (name && strcmp(name, enclave_attesters_ctx[i]->opts->name))
			continue;

		attester_ctx = malloc(sizeof(*attester_ctx));
		if (!attester_ctx)
			return -RATS_TLS_ERR_NO_MEM;

		memcpy(attester_ctx, enclave_attesters_ctx[i], sizeof(*attester_ctx));

		/* Set necessary configurations from rats_tls_init() to
		 * make init() working correctly.
		 */
		attester_ctx->enclave_id = ctx->config.enclave_id;
		attester_ctx->log_level = ctx->config.log_level;

		if (init_enclave_attester(ctx, attester_ctx, algo) == RATS_TLS_ERR_NONE)
			break;

		free(attester_ctx);
		attester_ctx = NULL;
	}

	if (!attester_ctx) {
		if (!name)
			RTLS_ERR("failed to select an enclave attester\n");
		else
			RTLS_ERR("failed to select the enclave attester '%s'\n", name);

		return -RATS_TLS_ERR_INVALID;
	}

	ctx->attester = attester_ctx;
	ctx->flags |= RATS_TLS_CTX_FLAGS_QUOTING_INITIALIZED;

	RTLS_INFO("the enclave attester '%s' selected\n", ctx->attester->opts->name);

	return RATS_TLS_ERR_NONE;
}
