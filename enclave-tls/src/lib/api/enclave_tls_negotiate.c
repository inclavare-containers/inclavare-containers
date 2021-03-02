#include <enclave-tls/api.h>
#include <enclave-tls/log.h>

#include "internal/core.h"

enclave_tls_err_t enclave_tls_negotiate(enclave_tls_handle handle, int fd)
{
	ETLS_DEBUG("--- Entering enclave_tls_negotiate ---\n");

	if (!handle || !(handle->tls_wrapper) ||
	    !(handle->tls_wrapper->opts) ||
	    !(handle->tls_wrapper->opts->negotiate) || fd < 0) {
		return -ENCLAVE_TLS_ERR_INVALID;
	}

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	etls_core_context_t *ctx = handle;
	/* Check whether need to generate certificate */
	if ((ctx->config.flags & ENCLAVE_TLS_CONF_FLAGS_SERVER) ||
	    (ctx->config.flags & ENCLAVE_TLS_CONF_FLAGS_MUTUAL)) {
		err = etls_core_generate_certificate(ctx);
		if (err != ENCLAVE_TLS_ERR_NONE) {
			ETLS_ERR("etls_core_generate_certificate err\n");
			return err;
		}
	}

	handle->tls_wrapper->fd = fd;
	err = handle->tls_wrapper->opts->negotiate(handle->tls_wrapper, fd);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("tls_wrapper negotiate error\n");
		return err;
	}

	return ENCLAVE_TLS_ERR_NONE;
}
