#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>

enclave_quote_err_t nullquote_cleanup(enclave_quote_ctx_t *ctx)
{
	ETLS_DEBUG("called\n");

	return ENCLAVE_QUOTE_ERR_NONE;
}
