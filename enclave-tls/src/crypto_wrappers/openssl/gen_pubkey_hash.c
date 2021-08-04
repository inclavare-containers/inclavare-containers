/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "openssl.h"

#define RSA_PUBKEY_3072_RAW_LEN 398

crypto_wrapper_err_t openssl_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
					     enclave_tls_cert_algo_t algo, uint8_t *hash)
{
	openssl_ctx *octx = NULL;

	ETLS_DEBUG("ctx %p, algo %d, hash %p\n", ctx, algo, hash);

	if (!ctx || !hash)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	octx = ctx->crypto_private;

	if (algo == ENCLAVE_TLS_CERT_ALGO_ECC_256_SHA256) {
		int len = i2d_EC_PUBKEY(octx->eckey, NULL);
		unsigned char buffer[len];
		unsigned char *p = buffer;

		len = i2d_EC_PUBKEY(octx->eckey, &p);

		SHA256(buffer, len, hash);

		ETLS_DEBUG(
			"the sha256 of public key [%d] %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x\n",
			len, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
			hash[28], hash[29], hash[30], hash[31]);

	} else if (algo == ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256) {
		int len = i2d_RSAPublicKey(octx->key, NULL);
		unsigned char buffer[len];
		unsigned char *p = buffer;

		len = i2d_RSAPublicKey(octx->key, &p);
		if (len != RSA_PUBKEY_3072_RAW_LEN)
			return -CRYPTO_WRAPPER_ERR_PUB_KEY_LEN;

		SHA256(buffer, len, hash);

		ETLS_DEBUG(
			"the sha256 of public key [%d] %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x\n",
			len, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
			hash[28], hash[29], hash[30], hash[31]);
	} else {
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	return CRYPTO_WRAPPER_ERR_NONE;
}
