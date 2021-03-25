#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/cert.h>

/* *INDENT-OFF* */
crypto_wrapper_err_t nullcrypto_gen_cert(crypto_wrapper_ctx_t *ctx,
					 enclave_tls_cert_info_t *cert_info)
{
	ETLS_DEBUG("ctx %p, cert_info %p\n", ctx, cert_info);

	return CRYPTO_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
