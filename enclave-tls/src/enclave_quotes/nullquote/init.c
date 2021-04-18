/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>

static unsigned int dummy_private;

enclave_quote_err_t nullquote_init(enclave_quote_ctx_t *ctx,
				   enclave_tls_cert_algo_t algo)
{
	ETLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	ctx->quote_private = &dummy_private;

	return ENCLAVE_QUOTE_ERR_NONE;
}