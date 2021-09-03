/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>

static unsigned int dummy_private;

tls_wrapper_err_t nulltls_init(tls_wrapper_ctx_t *ctx)
{
	RTLS_DEBUG("ctx %p\n", ctx);

	ctx->tls_private = &dummy_private;

	return TLS_WRAPPER_ERR_NONE;
}
