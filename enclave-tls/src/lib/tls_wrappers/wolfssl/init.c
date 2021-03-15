#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

#include "wolfssl_private.h"

 /* *INDENT-OFF* */
tls_wrapper_err_t wolfssl_init(tls_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("tls_wrapper_wolfssl init() called\n");

	tls_wrapper_err_t err = TLS_WRAPPER_ERR_NONE;

	wolfssl_ctx_t *ws_ctx = calloc(1, sizeof(*ws_ctx));
	if (!ws_ctx)
		return -TLS_WRAPPER_ERR_NO_MEM;

	wolfSSL_Init();

	if (ctx->log_level <= ENCLAVE_TLS_LOG_LEVEL_DEBUG)
		wolfSSL_Debugging_ON();
	else
		wolfSSL_Debugging_OFF();

	if (ctx->conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
		ws_ctx->ws = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
	else
		ws_ctx->ws = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!ws_ctx->ws) {
		err = -WOLFSSL_WRAPPER_ERR_CTX;
		goto err_wolfssl_ctx;
	}

	ctx->tls_private = ws_ctx;

	return TLS_WRAPPER_ERR_NONE;

err_wolfssl_ctx:
	wolfSSL_Cleanup();
	free(ws_ctx);
	return err;
}
/* *INDENT-ON* */
