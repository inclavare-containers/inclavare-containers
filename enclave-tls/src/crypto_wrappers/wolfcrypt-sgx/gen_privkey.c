/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/crypto_wrapper.h>
#include "wolfcrypt_sgx.h"

crypto_wrapper_err_t
wolfcrypt_sgx_gen_privkey(crypto_wrapper_ctx_t *ctx, enclave_tls_cert_algo_t algo,
			  uint8_t *privkey_buf, unsigned int *privkey_len)
{
	ETLS_DEBUG("ctx %p, algo %d, privkey_buf %p, privkey_len %p\n",
		   ctx, algo, privkey_buf, privkey_len);

	if (!ctx || !privkey_len)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	ETLS_DEBUG("calling init() with enclave id %lld ...\n", ctx->enclave_id);

	crypto_wrapper_err_t err;
	ecall_wolfcrypt_gen_privkey((sgx_enclave_id_t)ctx->enclave_id, &err, ctx, algo, privkey_buf, privkey_len);

	return err;
}
