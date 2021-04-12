#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl.h"

#ifndef WOLFSSL_SGX_WRAPPER
extern int verify_certificate(int preverify, WOLFSSL_X509_STORE_CTX *store);
#endif

tls_wrapper_err_t wolfssl_internal_negotiate(wolfssl_ctx_t *ws_ctx,
					     unsigned long conf_flags, int fd,
					     int (*verify)(int, WOLFSSL_X509_STORE_CTX *))
{
	if (verify)
		wolfSSL_CTX_set_verify(ws_ctx->ws, SSL_VERIFY_PEER, verify);

	WOLFSSL *ssl = wolfSSL_new(ws_ctx->ws);
	if (!ssl)
		return -TLS_WRAPPER_ERR_NO_MEM;

	/* Attach wolfSSL to the socket */
	wolfSSL_set_fd(ssl, fd);

	int err;
	if (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
		err = wolfSSL_negotiate(ssl);
	else
		err = wolfSSL_connect(ssl);

	if (err != SSL_SUCCESS) {
		if (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
			ETLS_DEBUG("failed to negotiate %#x\n", err);
		else
			ETLS_DEBUG("failed to connect %#x\n", err);

		print_wolfssl_err(ssl);

		return WOLFSSL_ERR_CODE(err);
	}

	ws_ctx->ssl = ssl;

	if (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
		ETLS_DEBUG("success to negotiate\n");
	else
		ETLS_DEBUG("success to connect\n");

	return TLS_WRAPPER_ERR_NONE;
}

#ifdef WOLFSSL_SGX_WRAPPER
static int ssl_ctx_set_verify_callback(int mode, WOLFSSL_X509_STORE_CTX *store)
{

    (void)mode;
    int result;
    int ret = ocall_verify_certificate(&result, store->certs->buffer, store->certs->length);
    return !ret;
}
#endif

tls_wrapper_err_t wolfssl_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	ETLS_DEBUG("ctx %p, fd %d\n", ctx, fd);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	int (*verify)(int, WOLFSSL_X509_STORE_CTX *) = NULL;
	unsigned long conf_flags = ctx->conf_flags;

	if (!(conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)) {
#ifdef WOLFSSL_SGX_WRAPPER
		verify = ssl_ctx_set_verify_callback;
#else
		verify = verify_certificate;
#endif
	}

	return wolfssl_internal_negotiate((wolfssl_ctx_t *)ctx->tls_private,
					  conf_flags, fd, verify);
}
