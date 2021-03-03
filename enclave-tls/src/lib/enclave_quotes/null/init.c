#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>

static unsigned int dummy_private;

/* *INDENT-OFF* */
enclave_quote_err_t null_init(enclave_quote_ctx_t *ctx,
			      enclave_tls_cert_algo_t algo)
{
	ETLS_DEBUG("enclave_quote_null init() is called\n");

	ctx->quote_private = &dummy_private;

	return ENCLAVE_QUOTE_ERR_NONE;
}
/* *INDENT-ON* */
