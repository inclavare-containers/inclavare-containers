/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "openssl.h"

crypto_wrapper_err_t openssl_cleanup(crypto_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	struct openssl_ctx *octx = ctx->crypto_private;

	if (octx->key)
		RSA_free(octx->key);

	free(octx);

	return CRYPTO_WRAPPER_ERR_NONE;
}
