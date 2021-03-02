#include <unistd.h>

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

/* *INDENT-OFF* */
tls_wrapper_err_t null_receive(tls_wrapper_ctx_t *ctx, void *buf, size_t *buf_size)
{
	ETLS_DEBUG("tls_wrapper_null receive() called\n");

	ssize_t rc = read(ctx->fd, buf, *buf_size);
	if (rc < 0) {
		ETLS_ERR("ERROR: null_receive()\n");
		return TLS_WRAPPER_ERR_RECEIVE;
	}
	*buf_size = rc;

	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
