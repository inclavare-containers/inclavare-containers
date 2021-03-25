#define _GNU_SOURCE
#include <string.h>
#include <assert.h>
#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl.h"

#ifndef SGX_ENCLAVE
extern int verify_certificate(int preverify, WOLFSSL_X509_STORE_CTX *store);
#endif

tls_wrapper_err_t wolfssl_internal_negotiate(wolfssl_ctx_t *ws_ctx,
					     unsigned long conf_flags, int fd,
					     int (*verify)(int, WOLFSSL_X509_STORE_CTX *))
{
	if (verify)
		wolfSSL_CTX_set_verify(ws_ctx->ws, SSL_VERIFY_PEER, verify);

	ws_ctx->ssl = wolfSSL_new(ws_ctx->ws);
	if (!ws_ctx->ssl)
		return -TLS_WRAPPER_ERR_UNKNOWN;

	/* Attach wolfSSL to the socket */
	wolfSSL_set_fd(ws_ctx->ssl, fd);

	int err;
	if (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
		err = wolfSSL_negotiate(ws_ctx->ssl);
	else
		err = wolfSSL_connect(ws_ctx->ssl);

	if (err != SSL_SUCCESS) {
		if (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
			ETLS_DEBUG("failed to negotiate %#x\n", err);
		else
			ETLS_DEBUG("failed to connect %#x\n", err);

		return WOLFSSL_ERR_CODE(err);
	}

	return TLS_WRAPPER_ERR_NONE;
}

#ifdef SGX_ENCLAVE
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

	int (*verify)(int, WOLFSSL_X509_STORE_CTX *) = NULL;

	unsigned long conf_flags = ctx->conf_flags;

	if (!(conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)) {
	#ifdef SGX_ENCLAVE
		verify = ssl_ctx_set_verify_callback;
	#else
		verify = verify_certificate;
	#endif
	}

	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private->tls_wrapper_private;

	return wolfssl_internal_negotiate(ws_ctx, conf_flags, fd, verify);
}
/* *INDENT-ON* */
