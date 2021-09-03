/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>

#include "sgx_la.h"

enclave_attester_err_t sgx_la_attester_init(enclave_attester_ctx_t *ctx,
					    rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	sgx_la_ctx_t *sgx_la_ctx = calloc(1, sizeof(*sgx_la_ctx));
	if (!sgx_la_ctx)
		return -ENCLAVE_ATTESTER_ERR_NO_MEM;

	sgx_la_ctx->eid = ctx->enclave_id;
	ctx->attester_private = sgx_la_ctx;

	return ENCLAVE_ATTESTER_ERR_NONE;
}
