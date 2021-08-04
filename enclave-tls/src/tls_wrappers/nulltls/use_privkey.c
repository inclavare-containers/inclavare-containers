/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

tls_wrapper_err_t nulltls_use_privkey(tls_wrapper_ctx_t *ctx, enclave_tls_cert_algo_t algo,
				      void *privkey_buf, size_t privkey_len)
{
	ETLS_DEBUG("ctx %p, privkey_buf %p, privkey_len %ld\n", ctx, privkey_buf, privkey_len);

	return TLS_WRAPPER_ERR_NONE;
}
