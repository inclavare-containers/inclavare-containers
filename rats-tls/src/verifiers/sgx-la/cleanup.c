/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include "sgx_la.h"

enclave_verifier_err_t sgx_la_verifier_cleanup(enclave_verifier_ctx_t *ctx)
{
	RTLS_DEBUG("called\n");

	sgx_la_ctx_t *la_ctx = (sgx_la_ctx_t *)ctx->verifier_private;

	free(la_ctx);

	return ENCLAVE_VERIFIER_ERR_NONE;
}
