/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>

static unsigned int dummy_private;

enclave_attester_err_t nullattester_init(enclave_attester_ctx_t *ctx, rats_tls_cert_algo_t algo)
{
	RTLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	ctx->attester_private = &dummy_private;

	return ENCLAVE_ATTESTER_ERR_NONE;
}
