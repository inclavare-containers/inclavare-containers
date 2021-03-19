#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

/* *INDENT-OFF* */
tls_wrapper_err_t null_use_cert(tls_wrapper_ctx_t *ctx,
				enclave_tls_cert_info_t *cert_info)
{
	ETLS_DEBUG("ctx %p, cert_info %p\n", ctx, cert_info);

	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
