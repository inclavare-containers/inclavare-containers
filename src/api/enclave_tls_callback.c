/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include "internal/core.h"

enclave_tls_err_t enclave_tls_set_verification_callback(enclave_tls_handle *handle,
							enclave_tls_callback_t cb)
{
	ETLS_DEBUG("set user verification callback handle: %p, cb %p\n", handle, cb);

	(*handle)->user_callback = cb;

	return ENCLAVE_TLS_ERR_NONE;
}
