/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>
#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>
#include <internal/core.h>
// clang-format off
#ifdef SGX
#include "rtls_t.h"
#endif
// clang-format on

tls_wrapper_err_t nulltls_transmit(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size)
{
	RTLS_DEBUG("ctx %p, buf %p, buf_size %p\n", ctx, buf, buf_size);

	ssize_t rc = rtls_write(ctx->fd, buf, *buf_size);
	if (rc < 0) {
		RTLS_DEBUG("ERROR: tls_wrapper_null transmit()\n");
		return TLS_WRAPPER_ERR_TRANSMIT;
	}

	*buf_size = (size_t)rc;

	return TLS_WRAPPER_ERR_NONE;
}
