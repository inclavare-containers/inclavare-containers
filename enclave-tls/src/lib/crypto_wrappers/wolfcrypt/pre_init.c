#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>

/* *INDENT-OFF* */
crypto_wrapper_err_t wolfcrypt_pre_init(void)
{
	ETLS_DEBUG("called\n");

	return CRYPTO_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
