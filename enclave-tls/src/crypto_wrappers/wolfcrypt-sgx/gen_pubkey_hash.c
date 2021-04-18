/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/crypto_wrapper.h>
#include "wolfcrypt_sgx.h"

crypto_wrapper_err_t wolfcrypt_sgx_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
						   enclave_tls_cert_algo_t algo,
						   uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, algo %d, hash %p\n", ctx, algo, hash);

	if (!ctx || !hash)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	ETLS_DEBUG("calling init() with enclave id %lld ...\n", ctx->enclave_id);
	
	crypto_wrapper_err_t err;
	ecall_wolfcrypt_gen_pubkey_hash((sgx_enclave_id_t)ctx->enclave_id, &err, ctx, algo, hash);

	return err;
}
