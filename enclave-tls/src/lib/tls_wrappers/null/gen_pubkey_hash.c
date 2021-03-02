#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

 /* *INDENT-OFF* */
tls_wrapper_err_t null_gen_pubkey_hash(tls_wrapper_ctx_t *ctx,
				       enclave_tls_cert_algo_t algo,
				       uint8_t *hash)
{
	ETLS_DEBUG("tls_wrapper_null gen_pubkey_hash is called\n");

	return TLS_WRAPPER_ERR_NONE;
}
 /* *INDENT-ON* */
