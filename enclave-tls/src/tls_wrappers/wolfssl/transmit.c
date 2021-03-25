#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl.h"

/* *INDENT-OFF* */
tls_wrapper_err_t wolfssl_transmit(tls_wrapper_ctx_t *ctx, void *buf,
				   size_t *buf_size)
{
	ETLS_DEBUG("tls_wrapper_wolfssl transmit() called\n");

	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private->tls_wrapper_private;
	if (ws_ctx == NULL || ws_ctx->ssl == NULL)
		return -TLS_WRAPPER_ERR_TRANSMIT;

	int rc = wolfSSL_write(ws_ctx->ssl, buf, *buf_size);
	if (rc <= 0) {
		ETLS_DEBUG("ERROR: tls_wrapper_wolfssl transmit()\n");
		return -TLS_WRAPPER_ERR_TRANSMIT;
	}
	*buf_size = rc;

	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
