/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/tls_wrapper.h>

tls_wrapper_err_t nulltls_use_privkey(tls_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
				      void *privkey_buf, size_t privkey_len)
{
	RTLS_DEBUG("ctx %p, algo %ld, privkey_buf %p, privkey_len %ld\n", ctx, algo, privkey_buf,
		   privkey_len);

	return TLS_WRAPPER_ERR_NONE;
}
