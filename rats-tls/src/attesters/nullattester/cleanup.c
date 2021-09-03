/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>

enclave_attester_err_t nullattester_cleanup(__attribute__((unused)) enclave_attester_ctx_t *ctx)
{
	RTLS_DEBUG("called\n");

	return ENCLAVE_ATTESTER_ERR_NONE;
}
