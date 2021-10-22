/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include "tdx.h"

enclave_verifier_err_t tdx_verifier_init(enclave_verifier_ctx_t *ctx, rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	tdx_ctx_t *tdx_ctx = calloc(1, sizeof(*tdx_ctx));
	if (!tdx_ctx)
		return -ENCLAVE_VERIFIER_ERR_NO_MEM;

	memset(tdx_ctx->mrowner, 0, MROWNER_SIZE);
	ctx->verifier_private = tdx_ctx;

	return ENCLAVE_VERIFIER_ERR_NONE;
}
