#include <unistd.h>

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

/* *INDENT-OFF* */
tls_wrapper_err_t null_transmit(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size)
{
	ETLS_DEBUG("tls_wrapper_null transmit() called\n");

	ssize_t rc = write(ctx->fd, buf, *buf_size);
	if (rc < 0) {
		ETLS_DEBUG("ERROR: tls_wrapper_null transmit()\n");
		return TLS_WRAPPER_ERR_TRANSMIT;
	}
	*buf_size = rc;

	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
