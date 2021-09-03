/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/core.h"
#include "internal/tls_wrapper.h"

static rats_tls_err_t init_tls_wrapper(tls_wrapper_ctx_t *tls_ctx)
{
	tls_wrapper_err_t err = tls_ctx->opts->init(tls_ctx);

	if (err != TLS_WRAPPER_ERR_NONE)
		return err;

	if (!tls_ctx->tls_private)
		return -RATS_TLS_ERR_INIT;

	return RATS_TLS_ERR_NONE;
}

rats_tls_err_t rtls_tls_wrapper_select(rtls_core_context_t *ctx, const char *name)
{
	RTLS_DEBUG("selecting the tls wrapper '%s' ...\n", name);

	tls_wrapper_ctx_t *tls_ctx = NULL;
	for (unsigned int i = 0; i < registerd_tls_wrapper_nums; ++i) {
		if (name && strcmp(name, tls_wrappers_ctx[i]->opts->name))
			continue;

		tls_ctx = malloc(sizeof(*tls_ctx));
		if (!tls_ctx)
			return -RATS_TLS_ERR_NO_MEM;

		*tls_ctx = *tls_wrappers_ctx[i];

		/* Set necessary configurations from rats_tls_init() to
		 * make init() working correctly.
		 */
		tls_ctx->conf_flags = ctx->config.flags;
		tls_ctx->enclave_id = ctx->config.enclave_id;
		tls_ctx->log_level = ctx->config.log_level;

		if (init_tls_wrapper(tls_ctx) == RATS_TLS_ERR_NONE)
			break;

		free(tls_ctx);
		tls_ctx = NULL;
	}

	if (!tls_ctx) {
		if (!name)
			RTLS_ERR("failed to select a tls wrapper\n");
		else
			RTLS_ERR("failed to select the tls wrapper '%s'\n", name);

		return -RATS_TLS_ERR_INIT;
	}

	ctx->tls_wrapper = tls_ctx;
	ctx->flags |= RATS_TLS_CTX_FLAGS_TLS_INITIALIZED;
	tls_ctx->rtls_handle = ctx;

	RTLS_INFO("the tls wrapper '%s' selected\n", tls_ctx->opts->name);

	return RATS_TLS_ERR_NONE;
}
