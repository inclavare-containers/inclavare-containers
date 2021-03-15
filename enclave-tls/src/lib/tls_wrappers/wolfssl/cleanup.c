#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

#include "wolfssl_private.h"

/* *INDENT-OFF* */
tls_wrapper_err_t wolfssl_cleanup(tls_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("tls_wrapper_wolfssl cleanup() called\n");

	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private;

	if (ws_ctx != NULL) {
		if (ws_ctx->ssl != NULL)
			wolfSSL_free(ws_ctx->ssl);
		if (ws_ctx->ws != NULL)
			wolfSSL_CTX_free(ws_ctx->ws);
	}
	free(ws_ctx);

	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
