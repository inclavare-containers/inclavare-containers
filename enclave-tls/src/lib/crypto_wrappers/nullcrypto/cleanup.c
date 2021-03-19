#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>

/* *INDENT-OFF* */
crypto_wrapper_err_t nullcrypto_cleanup(crypto_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	return CRYPTO_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
