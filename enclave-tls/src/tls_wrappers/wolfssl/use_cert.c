#define _GNU_SOURCE
#include <string.h>
#include <assert.h>
#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl.h"

tls_wrapper_err_t wolfssl_use_cert(tls_wrapper_ctx_t *ctx,
				   enclave_tls_cert_info_t *cert_info)
{
	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private->tls_wrapper_private;

	int ret = wolfSSL_CTX_use_certificate_buffer(ws_ctx->ws,
						     cert_info->cert_buf,
						     cert_info->cert_len,
						     SSL_FILETYPE_ASN1);
	if (ret != SSL_SUCCESS) {
		ETLS_ERR("failed to use certificate\n");
		return WOLFSSL_ERR_CODE(ret);
	}

	return TLS_WRAPPER_ERR_NONE;
}
