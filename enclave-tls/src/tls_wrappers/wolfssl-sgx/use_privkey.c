#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl_sgx.h"

tls_wrapper_err_t wolfssl_sgx_use_privkey(tls_wrapper_ctx_t *ctx,
					  void *privkey_buf,
					  size_t privkey_len)
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err;
	ecall_wolfssl_use_privkey((sgx_enclave_id_t)ctx->enclave_id, &err, ctx, privkey_buf, privkey_len);

	return err;
}
