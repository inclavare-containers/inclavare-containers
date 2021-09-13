/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/api.h>
#include <rats-tls/log.h>
#include "internal/core.h"

rats_tls_err_t rats_tls_negotiate(rats_tls_handle handle, int fd)
{
	rtls_core_context_t *ctx = (rtls_core_context_t *)handle;

	RTLS_DEBUG("handle %p, fd %d\n", ctx, fd);

	if (!ctx || !ctx->tls_wrapper || !ctx->tls_wrapper->opts ||
	    !ctx->tls_wrapper->opts->negotiate || fd < 0)
		return -RATS_TLS_ERR_INVALID;

	tls_wrapper_err_t t_err = ctx->tls_wrapper->opts->negotiate(ctx->tls_wrapper, fd);
	if (t_err != TLS_WRAPPER_ERR_NONE)
		return t_err;

	ctx->tls_wrapper->fd = fd;

	return RATS_TLS_ERR_NONE;
}
