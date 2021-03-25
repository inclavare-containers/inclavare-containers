#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>
#include "sgx_ecdsa.h"

/* *INDENT-OFF* */
enclave_quote_err_t sgx_ecdsa_cleanup(enclave_quote_ctx_t *ctx)
{
	ETLS_DEBUG("called\n");
	
	sgx_ecdsa_ctx_t *ecdsa_ctx = (sgx_ecdsa_ctx_t *)ctx->quote_private;

	free(ecdsa_ctx);

	return ENCLAVE_QUOTE_ERR_NONE;
}
/* *INDENT-ON* */
