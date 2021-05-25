/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>
#include "sgx_la.h"

enclave_quote_err_t sgx_la_cleanup(enclave_quote_ctx_t *ctx)
{
	ETLS_DEBUG("called\n");

	sgx_la_ctx_t *la_ctx = (sgx_la_ctx_t *)ctx->quote_private;

	free(la_ctx);

	return ENCLAVE_QUOTE_ERR_NONE;
}
