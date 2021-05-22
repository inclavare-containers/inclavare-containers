/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/api.h>
#include <enclave-tls/log.h>
#include <enclave-tls/cert.h>

extern crypto_wrapper_err_t wolfcrypt_sgx_pre_init(void);
extern crypto_wrapper_err_t wolfcrypt_sgx_init(crypto_wrapper_ctx_t *);
extern crypto_wrapper_err_t wolfcrypt_sgx_gen_privkey(crypto_wrapper_ctx_t *ctx,
						      enclave_tls_cert_algo_t algo,
						      uint8_t *privkey_buf,
						      unsigned int *privkey_len);
extern crypto_wrapper_err_t wolfcrypt_sgx_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
							  enclave_tls_cert_algo_t algo,
							  uint8_t * hash);
extern crypto_wrapper_err_t wolfcrypt_sgx_gen_cert(crypto_wrapper_ctx_t *ctx,
						   enclave_tls_cert_info_t *cert_info);
extern crypto_wrapper_err_t wolfcrypt_sgx_cleanup(crypto_wrapper_ctx_t *);

static crypto_wrapper_opts_t wolfcrypt_sgx_opts = {
	.api_version = CRYPTO_WRAPPER_API_VERSION_DEFAULT,
	.name = "wolfcrypt_sgx",
	.priority = 50,
	.pre_init = wolfcrypt_sgx_pre_init,
	.init = wolfcrypt_sgx_init,
	.gen_privkey = wolfcrypt_sgx_gen_privkey,
	.gen_pubkey_hash = wolfcrypt_sgx_gen_pubkey_hash,
	.gen_cert = wolfcrypt_sgx_gen_cert,
	.cleanup = wolfcrypt_sgx_cleanup,
	.flags = CRYPTO_WRAPPER_OPTS_FLAGS_SGX_ENCLAVE,
};

void __attribute__((constructor))libcrypto_wrapper_wolfcrypt_sgx_init(void)
{
	ETLS_DEBUG("called\n");

	crypto_wrapper_err_t err = crypto_wrapper_register(&wolfcrypt_sgx_opts);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		ETLS_ERR("failed to register the crypto wrapper 'wolfcrypt_sgx' %#x\n", err);
}
