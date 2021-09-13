/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <rats-tls/api.h>
#include <rats-tls/log.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"
#include "internal/tls_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"

rats_tls_err_t rats_tls_init(const rats_tls_conf_t *conf, rats_tls_handle *handle)
{
	if (!conf || !handle)
		return -RATS_TLS_ERR_INVALID;

	RTLS_DEBUG("conf %p, handle %p\n", conf, handle);

	rtls_core_context_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -RATS_TLS_ERR_NO_MEM;

	ctx->config = *conf;

	rats_tls_err_t err = -RATS_TLS_ERR_INVALID;

	if (ctx->config.api_version > RATS_TLS_API_VERSION_MAX) {
		RTLS_ERR("unsupported rats-tls api version %d > %d\n", ctx->config.api_version,
			 RATS_TLS_API_VERSION_MAX);
		goto err_ctx;
	}

	if (ctx->config.log_level < 0 || ctx->config.log_level >= RATS_TLS_LOG_LEVEL_MAX) {
		ctx->config.log_level = global_core_context.config.log_level;
		RTLS_WARN("log level reset to global value %d\n",
			  global_core_context.config.log_level);
	}

	if (ctx->config.cert_algo < 0 || ctx->config.cert_algo >= RATS_TLS_CERT_ALGO_MAX) {
		ctx->config.cert_algo = global_core_context.config.cert_algo;
		RTLS_WARN("certificate algorithm reset to global value %d\n",
			  global_core_context.config.cert_algo);
	}

	global_log_level = ctx->config.log_level;

	/* Select the target crypto wrapper to be used */
	char *choice = ctx->config.crypto_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.crypto_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = rtls_crypto_wrapper_select(ctx, choice);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target attester to be used */
	choice = ctx->config.attester_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.attester_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = rtls_attester_select(ctx, choice, ctx->config.cert_algo);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target verifier to be used */
	choice = ctx->config.verifier_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.verifier_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = rtls_verifier_select(ctx, choice, ctx->config.cert_algo);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target tls wrapper to be used */
	choice = ctx->config.tls_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.tls_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = rtls_tls_wrapper_select(ctx, choice);
	if (err != RATS_TLS_ERR_NONE)
		goto err_ctx;

	/* Check whether requiring to generate TLS certificate */
	if ((ctx->config.flags & RATS_TLS_CONF_FLAGS_SERVER) ||
	    (ctx->config.flags & RATS_TLS_CONF_FLAGS_MUTUAL)) {
		err = rtls_core_generate_certificate(ctx);
		if (err != RATS_TLS_ERR_NONE)
			goto err_ctx;
	}

	*handle = ctx;

	RTLS_DEBUG("the handle %p returned\n", ctx);

	return RATS_TLS_ERR_NONE;

err_ctx:
	free(ctx);
	return err;
}
