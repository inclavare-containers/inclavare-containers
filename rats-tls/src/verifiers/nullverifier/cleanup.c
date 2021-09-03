/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>

enclave_verifier_err_t nullverifier_cleanup(enclave_verifier_ctx_t *ctx)
{
	RTLS_DEBUG("called enclave verifier ctx: %#x\n", ctx);

	return ENCLAVE_VERIFIER_ERR_NONE;
}
