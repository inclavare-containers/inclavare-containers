#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

/* *INDENT-OFF* */
tls_wrapper_err_t null_pre_init(void)
{
	ETLS_DEBUG("tls_wrapper_null pre_init() called\n");

	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
