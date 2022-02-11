/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include "openssl.h"

tls_wrapper_err_t openssl_tls_cleanup(tls_wrapper_ctx_t *ctx)
{
	RTLS_DEBUG("ctx %p\n", ctx);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;

	if (ssl_ctx != NULL) {
		if (ssl_ctx->ssl != NULL) {
			SSL_shutdown(ssl_ctx->ssl);
			SSL_free(ssl_ctx->ssl);
		}
		if (ssl_ctx->sctx != NULL)
			SSL_CTX_free(ssl_ctx->sctx);
	}
	free(ssl_ctx);

	return TLS_WRAPPER_ERR_NONE;
}
