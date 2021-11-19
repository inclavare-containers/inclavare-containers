/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include "../../verifiers/tdx-ecdsa/tdx-ecdsa.h"

enclave_attester_err_t tdx_ecdsa_attester_init(enclave_attester_ctx_t *ctx,
					       rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	tdx_ctx_t *tdx_ctx = calloc(1, sizeof(*tdx_ctx));
	if (!tdx_ctx)
		return -ENCLAVE_ATTESTER_ERR_NO_MEM;

	memset(tdx_ctx->mrowner, 0, sizeof(tdx_ctx->mrowner));
	ctx->attester_private = tdx_ctx;

	return ENCLAVE_ATTESTER_ERR_NONE;
}
