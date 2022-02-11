/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>

tls_wrapper_err_t nulltls_pre_init(void)
{
	RTLS_DEBUG("called\n");

	return TLS_WRAPPER_ERR_NONE;
}