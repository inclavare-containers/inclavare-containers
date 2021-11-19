/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/tls_wrapper.h>
#include <rats-tls/log.h>
#include <rats-tls/cert.h>

extern tls_wrapper_err_t openssl_tls_pre_init(void);
extern tls_wrapper_err_t openssl_tls_init(tls_wrapper_ctx_t *);
extern tls_wrapper_err_t openssl_tls_use_privkey(tls_wrapper_ctx_t *ctx, rats_tls_cert_algo_t algo,
						 void *privkey_buf, size_t privkey_len);
extern tls_wrapper_err_t openssl_tls_use_cert(tls_wrapper_ctx_t *ctx,
					      rats_tls_cert_info_t *cert_info);
extern tls_wrapper_err_t openssl_tls_negotiate(tls_wrapper_ctx_t *, int fd);
extern tls_wrapper_err_t openssl_tls_transmit(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t openssl_tls_receive(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t openssl_tls_cleanup(tls_wrapper_ctx_t *);

static tls_wrapper_opts_t openssl_opts = {
	.api_version = TLS_WRAPPER_API_VERSION_DEFAULT,
	.name = "openssl",
	.priority = 25,
	.pre_init = openssl_tls_pre_init,
	.init = openssl_tls_init,
	.use_privkey = openssl_tls_use_privkey,
	.use_cert = openssl_tls_use_cert,
	.negotiate = openssl_tls_negotiate,
	.transmit = openssl_tls_transmit,
	.receive = openssl_tls_receive,
	.cleanup = openssl_tls_cleanup,
};

#ifdef SGX
void libtls_wrapper_openssl_init(void)
#else
void __attribute__((constructor)) libtls_wrapper_openssl_init(void)
#endif
{
	RTLS_DEBUG("called\n");

	tls_wrapper_err_t err = tls_wrapper_register(&openssl_opts);
	if (err != TLS_WRAPPER_ERR_NONE)
		RTLS_ERR("failed to register the tls wrapper 'openssl' %#x\n", err);
}
