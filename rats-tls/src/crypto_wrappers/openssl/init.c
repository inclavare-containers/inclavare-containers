/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <rats-tls/log.h>
#include <rats-tls/crypto_wrapper.h>
#include "openssl.h"

crypto_wrapper_err_t openssl_init(crypto_wrapper_ctx_t *ctx)
{
	openssl_ctx *octx = NULL;

	RTLS_DEBUG("ctx %p\n", ctx);

	octx = calloc(1, sizeof(*octx));
	if (!octx)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	ctx->crypto_private = octx;

	return CRYPTO_WRAPPER_ERR_NONE;
}
