/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include "tdx.h"

enclave_attester_err_t tdx_attester_cleanup(enclave_attester_ctx_t *ctx)
{
	RTLS_DEBUG("called\n");

	tdx_ctx_t *tdx_ctx = (tdx_ctx_t *)ctx->attester_private;

	free(tdx_ctx);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
