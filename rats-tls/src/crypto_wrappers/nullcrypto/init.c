/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/crypto_wrapper.h>

static unsigned int dummy_private;

crypto_wrapper_err_t nullcrypto_init(crypto_wrapper_ctx_t *ctx)
{
	RTLS_DEBUG("ctx %p\n", ctx);

	ctx->crypto_private = &dummy_private;

	return CRYPTO_WRAPPER_ERR_NONE;
}
