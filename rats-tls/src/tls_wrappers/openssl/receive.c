/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include "openssl.h"

tls_wrapper_err_t openssl_tls_receive(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size)
{
	RTLS_DEBUG("ctx %p, buf %p, buf_size %p\n", ctx, buf, buf_size);

	if (!ctx || !buf || !buf_size)
		return -TLS_WRAPPER_ERR_INVALID;

	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;
	if (ssl_ctx == NULL || ssl_ctx->ssl == NULL)
		return -TLS_WRAPPER_ERR_RECEIVE;

	int rc = SSL_read(ssl_ctx->ssl, buf, (int)*buf_size);
	if (rc <= 0) {
		RTLS_ERR("ERROR: openssl_receive()\n");
		return -TLS_WRAPPER_ERR_RECEIVE;
	}
	*buf_size = (size_t)rc;

	return TLS_WRAPPER_ERR_NONE;
}
