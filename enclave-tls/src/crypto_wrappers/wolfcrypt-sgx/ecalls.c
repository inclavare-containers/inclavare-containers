/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include "sgx_stub_t.h"
#include "../wolfcrypt/pre_init.c"
#include "../wolfcrypt/init.c"
#include "../wolfcrypt/gen_privkey.c"
#include "../wolfcrypt/gen_pubkey_hash.c"
#include "../wolfcrypt/gen_cert.c"
#include "../wolfcrypt/cleanup.c"

crypto_wrapper_err_t ecall_wolfcrypt_pre_init(void)
{
	return wolfcrypt_pre_init();
}

crypto_wrapper_err_t ecall_wolfcrypt_init(crypto_wrapper_ctx_t *ctx)
{
	return wolfcrypt_init(ctx);
}

crypto_wrapper_err_t ecall_wolfcrypt_gen_privkey(crypto_wrapper_ctx_t *ctx,
						 enclave_tls_cert_algo_t algo,
						 uint8_t *privkey_buf,
						 unsigned int *privkey_len)
{
	return wolfcrypt_gen_privkey(ctx, algo, privkey_buf, privkey_len);
}

crypto_wrapper_err_t ecall_wolfcrypt_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
						     enclave_tls_cert_algo_t algo,
						     uint8_t *hash)
{
	return wolfcrypt_gen_pubkey_hash(ctx, algo, hash);
}

crypto_wrapper_err_t ecall_wolfcrypt_gen_cert(crypto_wrapper_ctx_t *ctx,
					      enclave_tls_cert_info_t *cert_info)
{
	return wolfcrypt_gen_cert(ctx, cert_info);
}

crypto_wrapper_err_t ecall_wolfcrypt_cleanup(crypto_wrapper_ctx_t *ctx)
{
	return wolfcrypt_cleanup(ctx);
}
