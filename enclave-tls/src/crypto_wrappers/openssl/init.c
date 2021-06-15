/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "openssl.h"

crypto_wrapper_err_t openssl_init(crypto_wrapper_ctx_t *ctx)
{
	struct openssl_ctx *octx;

	ETLS_DEBUG("ctx %p\n", ctx);

	octx = calloc(1, sizeof(*octx));
	if (!octx)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	ctx->crypto_private = octx;

	return CRYPTO_WRAPPER_ERR_NONE;
}
