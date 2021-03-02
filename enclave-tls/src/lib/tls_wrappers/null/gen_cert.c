#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

/* *INDENT-OFF* */
tls_wrapper_err_t null_gen_cert(tls_wrapper_ctx_t *ctx,
				const tls_wrapper_cert_info_t *cert_info)
{
	ETLS_DEBUG("tls_wrapper_null gen_cert is called\n");

	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
