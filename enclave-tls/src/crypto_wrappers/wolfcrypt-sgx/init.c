#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "wolfcrypt_sgx.h"

crypto_wrapper_err_t wolfcrypt_sgx_init(crypto_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	if (!ctx)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	ETLS_DEBUG("calling init() with enclave id %lld ...\n", ctx->enclave_id);

	crypto_wrapper_err_t err;
	ecall_wolfcrypt_init((sgx_enclave_id_t)ctx->enclave_id, &err, ctx);

	return err;
}
