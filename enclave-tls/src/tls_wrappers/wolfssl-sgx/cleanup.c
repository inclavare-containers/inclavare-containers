#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl_sgx.h"

tls_wrapper_err_t wolfssl_sgx_cleanup(tls_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err;
	ecall_wolfssl_cleanup((sgx_enclave_id_t)ctx->enclave_id, &err, ctx);

	return err;
}
