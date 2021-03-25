#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl_sgx.h"

tls_wrapper_err_t wolfssl_sgx_use_privkey(tls_wrapper_ctx_t *ctx,
					  void *__secured privkey_buf,
					  size_t privkey_len)
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err;
	sgx_enclave_id_t eid = ctx->tls_private->config.eid;

	ecall_use_privkey(eid, &err, ctx, privkey_buf, privkey_len);

	return err;
}
