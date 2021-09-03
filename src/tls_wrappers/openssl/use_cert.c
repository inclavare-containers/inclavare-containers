/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include "openssl.h"

tls_wrapper_err_t openssl_tls_use_cert(tls_wrapper_ctx_t *ctx, rats_tls_cert_info_t *cert_info)
{
	RTLS_DEBUG("ctx %p, cert_info %p\n", ctx, cert_info);

	if (!ctx || !cert_info)
		return -TLS_WRAPPER_ERR_INVALID;

	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;
	int ret = SSL_CTX_use_certificate_ASN1(ssl_ctx->sctx, cert_info->cert_len,
					       cert_info->cert_buf);
	if (ret != SSL_SUCCESS) {
		RTLS_ERR("failed to use certificate %d\n", ret);
		return OPENSSL_ERR_CODE(ret);
	}

	return TLS_WRAPPER_ERR_NONE;
}
