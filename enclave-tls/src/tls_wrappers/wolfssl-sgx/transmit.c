/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl_sgx.h"

tls_wrapper_err_t wolfssl_sgx_transmit(tls_wrapper_ctx_t *ctx, void *buf,
				       size_t *buf_size)
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err;
	ecall_wolfssl_transmit((sgx_enclave_id_t)ctx->enclave_id, &err, ctx, buf, buf_size);

	return err;
}
