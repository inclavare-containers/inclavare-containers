/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "openssl.h"

crypto_wrapper_err_t openssl_gen_privkey(crypto_wrapper_ctx_t *ctx, enclave_tls_cert_algo_t algo,
					 uint8_t *privkey_buf, unsigned int *privkey_len)
{
	openssl_ctx *octx = NULL;
	unsigned char *p = privkey_buf;
	EC_GROUP *group = NULL;
	BIGNUM *e = NULL;
	int len = 0;
	int ret;

	ETLS_DEBUG("ctx %p, algo %d, privkey_buf %p, privkey_len %p\n", ctx, algo, privkey_buf,
		   privkey_len);

	if (!ctx || !privkey_len)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	if (privkey_buf != NULL && *privkey_len == 0)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	ETLS_DEBUG("%d-byte private key buffer requested ...\n", *privkey_len);

	octx = ctx->crypto_private;

	ret = -CRYPTO_WRAPPER_ERR_NO_MEM;

	if (algo == ENCLAVE_TLS_CERT_ALGO_ECC_256_SHA256) {
		octx->eckey = EC_KEY_new();
		if (octx->eckey == NULL)
			goto err;

		ret = -CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;

		/* P_CURVE_256 */
		int nid = NID_X9_62_prime256v1;
		group = EC_GROUP_new_by_curve_name(nid);
		if (group == NULL)
			goto err;

		if (EC_KEY_set_group(octx->eckey, group) == 0)
			goto err;

		EC_GROUP_free(group);

		/* Get elliptic curve key length */
		len = EC_GROUP_get_degree(EC_KEY_get0_group(octx->eckey));
		if (len < 160) {
			/* drop the curve */
			ETLS_DEBUG(
				"# FAIL: As the degree is less than 160, Drop the curve from processing\n");
			goto err;
		}

		/* Generating public-private key */
		if (!EC_KEY_generate_key(octx->eckey))
			goto err;

		/* check key */
		if (!EC_KEY_check_key(octx->eckey))
			goto err;

		/* Encode elliptic curve key Der */
		len = i2d_ECPrivateKey(octx->eckey, NULL);
		if (len < 0)
			goto err;

		if (p == NULL) {
			*privkey_len = len;
			return CRYPTO_WRAPPER_ERR_NONE;
		}

		ret = -CRYPTO_WRAPPER_ERR_ECC_KEY_LEN;

		if (*privkey_len < len)
			goto err;

		len = i2d_ECPrivateKey(octx->eckey, &p);
		if (len < 0)
			goto err;

		ETLS_DEBUG("ECC-256 private key (%d-byte) in DER format generated\n", len);

	} else if (algo == ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256) {
		octx->key = RSA_new();
		if (octx->key == NULL)
			goto err;

		if ((e = BN_new()) == NULL)
			goto err;

		ret = -CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;
		BN_set_word(e, RSA_F4);
		if (!RSA_generate_key_ex(octx->key, 3072, e, NULL))
			goto err;

		len = i2d_RSAPrivateKey(octx->key, NULL);
		if (len < 0)
			goto err;

		if (p == NULL) {
			*privkey_len = len;
			return CRYPTO_WRAPPER_ERR_NONE;
		}

		ret = -CRYPTO_WRAPPER_ERR_RSA_KEY_LEN;

		if (*privkey_len < len)
			goto err;

		len = i2d_RSAPrivateKey(octx->key, &p);
		if (len < 0)
			goto err;

		ETLS_DEBUG("RSA-3072 private key (%d-byte) in DER format generated\n", len);
	} else {
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	*privkey_len = len;

	return CRYPTO_WRAPPER_ERR_NONE;

err:
	if (algo == ENCLAVE_TLS_CERT_ALGO_ECC_256_SHA256) {
		ETLS_DEBUG("failed to generate ECC-256 private key %d\n", ret);

		if (octx->eckey) {
			EC_KEY_free(octx->eckey);
			octx->eckey = NULL;
		}

		if (group)
			EC_GROUP_free(group);
	} else if (algo == ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256) {
		ETLS_DEBUG("failed to generate RSA-3072 private key %d\n", ret);

		if (octx->key) {
			RSA_free(octx->key);
			octx->key = NULL;
		}

		if (e)
			BN_free(e);
	}
	return ret;
}
