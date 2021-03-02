#include <enclave-tls/log.h>
#include <enclave-tls/err.h>

#include "internal/core.h"
#include "internal/tls_wrapper.h"
#include "internal/enclave_quote.h"

etls_core_context_t global_core_context;
enclave_tls_log_level_t global_log_level = ENCLAVE_TLS_LOG_LEVEL_DEBUG;

/* *INDENT-OFF* */
void __attribute__((constructor))
libenclave_tls_init(void)
{
	ETLS_DEBUG("The constructor of libenclave_tls.so is called\n");

	/* Initialize global variables, Leave tls_type blank to use the default
	 * TLS Wrapper instance, attester_type and verifier_type are left blank 
	 * to use the default Quote instance.
	 */
	global_core_context.config.api_version = ENCLAVE_TLS_API_VERSION_DEFAULT;
	global_core_context.config.log_level = ENCLAVE_TLS_LOG_LEVEL_DEFAULT;
	global_core_context.config.cert_algo = ENCLAVE_TLS_CERT_ALGO_DEFAULT;

	/* Load all Enclave Quote instances */
	if (etls_enclave_quote_load_all() != ENCLAVE_TLS_ERR_NONE) {
		ETLS_ERR("Not detected valid Enclave Quote instance\n");
	}

	/* Load all Tls Wrapper instances */
	if (etls_tls_wrapper_load_all() != ENCLAVE_TLS_ERR_NONE) {
		ETLS_ERR("Not detected valid TLS Wrapper instance\n");
	}
}
/* *INDENT-ON* */
