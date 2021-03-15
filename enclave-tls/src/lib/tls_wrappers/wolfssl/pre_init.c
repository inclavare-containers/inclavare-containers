#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

/* *INDENT-OFF* */
tls_wrapper_err_t wolfssl_pre_init(void)
{
	ETLS_DEBUG("tls_wrapper_wolfssl pre_init() called\n");

	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
