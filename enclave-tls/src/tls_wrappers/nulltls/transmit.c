/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>
#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

tls_wrapper_err_t nulltls_transmit(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size)
{
	ETLS_DEBUG("ctx %p, buf %p, buf_size %p\n", ctx, buf, buf_size);

	ssize_t rc = write(ctx->fd, buf, *buf_size);
	if (rc < 0) {
		ETLS_DEBUG("ERROR: tls_wrapper_null transmit()\n");
		return TLS_WRAPPER_ERR_TRANSMIT;
	}
	*buf_size = rc;

	return TLS_WRAPPER_ERR_NONE;
}
