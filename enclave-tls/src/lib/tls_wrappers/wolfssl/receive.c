#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

#include "wolfssl_private.h"

/* *INDENT-OFF* */
tls_wrapper_err_t wolfssl_receive(tls_wrapper_ctx_t *ctx, void *buf,
				  size_t *buf_size)
{
	ETLS_DEBUG("tls_wrapper_wolfssl receive() called\n");

	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private;
	if (ws_ctx == NULL || ws_ctx->ssl == NULL)
		return -TLS_WRAPPER_ERR_RECEIVE;

	int rc = wolfSSL_read(ws_ctx->ssl, buf, *buf_size);
	if (rc <= 0) {
		ETLS_ERR("ERROR: wolfssl_receive()\n");
		return -TLS_WRAPPER_ERR_RECEIVE;
	}
	*buf_size = rc;

	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
