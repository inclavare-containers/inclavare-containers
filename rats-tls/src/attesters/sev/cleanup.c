/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/attester.h>
#include <rats-tls/log.h>

enclave_attester_err_t sev_cleanup(enclave_attester_ctx_t *ctx)
{
	RTLS_DEBUG("called\n");

	return ENCLAVE_ATTESTER_ERR_NONE;
}
