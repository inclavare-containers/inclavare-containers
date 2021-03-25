#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

 /* *INDENT-OFF* */
tls_wrapper_err_t null_init(tls_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("tls_wrapper_null init() called\n");

	return TLS_WRAPPER_ERR_NONE;
}
 /* *INDENT-ON* */
