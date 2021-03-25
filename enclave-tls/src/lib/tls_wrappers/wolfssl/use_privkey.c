#define _GNU_SOURCE
#include <string.h>
#include <assert.h>
#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl_private.h"

tls_wrapper_err_t __secured
wolfssl_use_privkey(tls_wrapper_ctx_t *ctx,
		    void *__secured privkey_buf, size_t privkey_len)
{
	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private->tls_wrapper_private;

	int ret = wolfSSL_CTX_use_PrivateKey_buffer(ws_ctx->ws,
						    privkey_buf,
						    privkey_len,
						    SSL_FILETYPE_ASN1);
	if (ret != SSL_SUCCESS) {
		ETLS_ERR("failed to use private key %d\n", ret);
		return WOLFSSL_ERR_CODE(ret);
	}

	return TLS_WRAPPER_ERR_NONE;
}
