/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/log.h>
#include <enclave-tls/cert.h>

crypto_wrapper_err_t openssl_pre_init(void);
crypto_wrapper_err_t openssl_init(crypto_wrapper_ctx_t *ctx);
crypto_wrapper_err_t openssl_gen_privkey(crypto_wrapper_ctx_t *ctx,
					 enclave_tls_cert_algo_t algo,
					 uint8_t *privkey_buf,
					 unsigned int *privkey_len);
crypto_wrapper_err_t openssl_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
					     enclave_tls_cert_algo_t algo,
					     uint8_t *hash);
crypto_wrapper_err_t openssl_gen_cert(crypto_wrapper_ctx_t *ctx,
				      enclave_tls_cert_info_t *cert_info);
crypto_wrapper_err_t openssl_cleanup(crypto_wrapper_ctx_t *ctx);

static const crypto_wrapper_opts_t openssl_opts = {
	.api_version		= CRYPTO_WRAPPER_API_VERSION_DEFAULT,
	.name			= "openssl",
	.priority		= 25,
	.pre_init		= openssl_pre_init,
	.init			= openssl_init,
	.gen_privkey		= openssl_gen_privkey,
	.gen_pubkey_hash	= openssl_gen_pubkey_hash,
	.gen_cert		= openssl_gen_cert,
	.cleanup		= openssl_cleanup,
};

static void __attribute__((constructor)) libcrypto_wrapper_openssl_init(void)
{
	ETLS_DEBUG("called\n");

	crypto_wrapper_err_t err = crypto_wrapper_register(&openssl_opts);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		ETLS_ERR("failed to register the crypto wrapper 'openssl' %#x\n", err);
}
