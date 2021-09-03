/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/crypto_wrapper.h>
#include <rats-tls/cert.h>

crypto_wrapper_err_t nullcrypto_gen_cert(crypto_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
					 rats_tls_cert_info_t *cert_info)
{
	RTLS_DEBUG("ctx %p, algo is %d, cert_info %p\n", ctx, algo, cert_info);

	return CRYPTO_WRAPPER_ERR_NONE;
}
