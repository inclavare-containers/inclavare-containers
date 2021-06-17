/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "openssl.h"

tls_wrapper_err_t openssl_tls_cleanup(tls_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;

	if (ssl_ctx != NULL) {
		if (ssl_ctx->ssl != NULL)
			SSL_free(ssl_ctx->ssl);
		if (ssl_ctx->sctx != NULL)
			SSL_CTX_free(ssl_ctx->sctx);
	}
	free(ssl_ctx);

	return TLS_WRAPPER_ERR_NONE;
}
