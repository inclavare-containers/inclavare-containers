#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>

enclave_quote_err_t null_pre_init(void)
{
	ETLS_DEBUG("enclave_quote_null pre_init() is called\n");

	return ENCLAVE_QUOTE_ERR_NONE;
}
