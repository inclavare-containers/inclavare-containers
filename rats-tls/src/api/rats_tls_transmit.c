/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/api.h>
#include <rats-tls/log.h>

#include "internal/core.h"

rats_tls_err_t rats_tls_transmit(rats_tls_handle handle, void *buf, size_t *buf_size)
{
	rtls_core_context_t *ctx = (rtls_core_context_t *)handle;

	RTLS_DEBUG("handle %p, buf %p, buf_size %p (%Zd-byte)\n", ctx, buf, buf_size, *buf_size);

	if (!handle || !handle->tls_wrapper || !handle->tls_wrapper->opts ||
	    !handle->tls_wrapper->opts->transmit || !buf || !buf_size)
		return -RATS_TLS_ERR_INVALID;

	tls_wrapper_err_t err =
		handle->tls_wrapper->opts->transmit(handle->tls_wrapper, buf, buf_size);
	if (err != TLS_WRAPPER_ERR_NONE)
		return -RATS_TLS_ERR_INVALID;

	return RATS_TLS_ERR_NONE;
}
