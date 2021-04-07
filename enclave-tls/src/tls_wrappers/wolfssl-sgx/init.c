#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl_sgx.h"

tls_wrapper_err_t wolfssl_sgx_init(tls_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	if (!ctx)
		return -TLS_WRAPPER_ERR_INVALID;

	ETLS_DEBUG("calling init() with enclave id %llu ...\n", ctx->enclave_id);

	tls_wrapper_err_t err;
	ecall_wolfssl_init((sgx_enclave_id_t)ctx->enclave_id, &err, ctx);

	return err;
}
