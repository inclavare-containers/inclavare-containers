/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include "sgx_ecdsa.h"

enclave_verifier_err_t sgx_ecdsa_verifier_init(enclave_verifier_ctx_t *ctx,
					       rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	sgx_ecdsa_ctx_t *sgx_ecdsa_ctx = calloc(1, sizeof(*sgx_ecdsa_ctx));
	if (!sgx_ecdsa_ctx)
		return -ENCLAVE_VERIFIER_ERR_NO_MEM;

	sgx_ecdsa_ctx->eid = ctx->enclave_id;
	ctx->verifier_private = sgx_ecdsa_ctx;

	return ENCLAVE_VERIFIER_ERR_NONE;
}
