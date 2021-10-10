/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include "tdx.h"

enclave_verifier_err_t tdx_verifier_cleanup(enclave_verifier_ctx_t *ctx)
{
	RTLS_DEBUG("called\n");

	tdx_ctx_t *tdx_ctx = (tdx_ctx_t *)ctx->verifier_private;

	free(tdx_ctx);

	return ENCLAVE_VERIFIER_ERR_NONE;
}
