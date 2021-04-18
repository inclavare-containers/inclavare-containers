/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/cert.h>
#include "wolfcrypt_sgx.h"

crypto_wrapper_err_t
wolfcrypt_sgx_gen_cert(crypto_wrapper_ctx_t *ctx,
		       enclave_tls_cert_info_t *cert_info)
{
	ETLS_DEBUG("ctx %p, cert_info %p\n", ctx, cert_info);

	if (!ctx || !cert_info)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	ETLS_DEBUG("calling init() with enclave id %lld ...\n", ctx->enclave_id);

	crypto_wrapper_err_t err;
	ecall_wolfcrypt_gen_cert((sgx_enclave_id_t)ctx->enclave_id, &err, ctx, cert_info);

	return err;
}
