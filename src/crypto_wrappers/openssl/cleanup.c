/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <rats-tls/log.h>
#include <rats-tls/crypto_wrapper.h>
#include "openssl.h"

crypto_wrapper_err_t openssl_cleanup(crypto_wrapper_ctx_t *ctx)
{
	RTLS_DEBUG("ctx %p\n", ctx);

	openssl_ctx *octx = ctx->crypto_private;

	/* octx->key has been freed by EVP_PKEY_free() */
	free(octx);

	return CRYPTO_WRAPPER_ERR_NONE;
}
