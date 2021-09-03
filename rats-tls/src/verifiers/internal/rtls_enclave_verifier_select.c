/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/verifier.h"
#include "internal/core.h"

static rats_tls_err_t init_enclave_verifier(rtls_core_context_t *ctx,
					       enclave_verifier_ctx_t *verifier_ctx,
					       rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("init enclave verifier rtls_core_context: %#x\n", ctx);
	enclave_verifier_err_t err = verifier_ctx->opts->init(verifier_ctx, algo);

	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		return -RATS_TLS_ERR_INIT;

	if (!verifier_ctx->verifier_private)
		return -RATS_TLS_ERR_INIT;

	return RATS_TLS_ERR_NONE;
}

rats_tls_err_t rtls_verifier_select(rtls_core_context_t *ctx, const char *name,
				       rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("selecting the enclave verifier '%s' ...\n", name);

	enclave_verifier_ctx_t *verifier_ctx = NULL;
	for (unsigned int i = 0; i < registerd_enclave_verifier_nums; ++i) {
		if (name && strcmp(name, enclave_verifiers_ctx[i]->opts->name))
			continue;

		verifier_ctx = malloc(sizeof(*verifier_ctx));
		if (!verifier_ctx)
			return -RATS_TLS_ERR_NO_MEM;

		memcpy(verifier_ctx, enclave_verifiers_ctx[i], sizeof(*verifier_ctx));

		/* Set necessary configurations from rats_tls_init() to
		 * make init() working correctly.
		 */
		verifier_ctx->enclave_id = ctx->config.enclave_id;
		verifier_ctx->log_level = ctx->config.log_level;

		if (init_enclave_verifier(ctx, verifier_ctx, algo) == RATS_TLS_ERR_NONE)
			break;

		free(verifier_ctx);
		verifier_ctx = NULL;
	}

	if (!verifier_ctx) {
		if (!name)
			RTLS_ERR("failed to select an enclave verifier\n");
		else
			RTLS_ERR("failed to select the enclave verifier '%s'\n", name);

		return -RATS_TLS_ERR_INVALID;
	}

	ctx->verifier = verifier_ctx;

	RTLS_INFO("the enclave verifier '%s' selected\n", ctx->verifier->opts->name);

	return RATS_TLS_ERR_NONE;
}
