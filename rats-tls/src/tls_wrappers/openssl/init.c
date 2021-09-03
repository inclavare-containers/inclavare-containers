/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include "per_thread.h"
#include "openssl.h"

tls_wrapper_err_t openssl_tls_init(tls_wrapper_ctx_t *ctx)
{
	RTLS_DEBUG("ctx %p\n", ctx);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	if (SSL_library_init() < 0) {
		RTLS_ERR("failed to initialize the openssl library\n");
		return -TLS_WRAPPER_ERR_NOT_FOUND;
	}

	openssl_ctx_t *ssl_ctx = calloc(1, sizeof(*ssl_ctx));
	if (!ssl_ctx)
		return -TLS_WRAPPER_ERR_NO_MEM;

	if (ctx->conf_flags & RATS_TLS_CONF_FLAGS_SERVER)
		ssl_ctx->sctx = SSL_CTX_new(TLS_server_method());
	else
		ssl_ctx->sctx = SSL_CTX_new(TLS_client_method());

	if (!ssl_ctx->sctx) {
		free(ssl_ctx);
		RTLS_ERR("failed to init openssl ctx\n");
		return -TLS_WRAPPER_ERR_NO_MEM;
	}

	ctx->tls_private = ssl_ctx;

	per_thread_key_init();

	return TLS_WRAPPER_ERR_NONE;
}
