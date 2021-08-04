/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "openssl.h"

tls_wrapper_err_t openssl_tls_use_privkey(tls_wrapper_ctx_t *ctx, enclave_tls_cert_algo_t algo,
					  void *privkey_buf, size_t privkey_len)
{
	ETLS_DEBUG("ctx %p, privkey_buf %p, privkey_len %zu\n", ctx, privkey_buf, privkey_len);

	if (!ctx || !privkey_buf || !privkey_len)
		return -TLS_WRAPPER_ERR_INVALID;

	openssl_ctx_t *ssl_ctx = (openssl_ctx_t *)ctx->tls_private;

	int ret;
	int EVP_PKEY;

	if (algo == ENCLAVE_TLS_CERT_ALGO_ECC_256_SHA256) {
		EVP_PKEY = EVP_PKEY_EC;
	} else if (algo == ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256) {
		EVP_PKEY = EVP_PKEY_RSA;
	} else {
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	ret = SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY, ssl_ctx->sctx, privkey_buf, (long)privkey_len);

	if (ret != SSL_SUCCESS) {
		ETLS_ERR("failed to use private key %d\n", ret);
		return OPENSSL_ERR_CODE(ret);
	}

	return TLS_WRAPPER_ERR_NONE;
}
