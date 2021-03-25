#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl_sgx.h"

tls_wrapper_err_t wolfssl_sgx_transmit(tls_wrapper_ctx_t *ctx, void *buf,
				       size_t *buf_size)
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err;
	sgx_enclave_id_t eid = ctx->tls_private->config.eid;

	ecall_transmit(eid, &err, ctx, buf, buf_size);

	return err;
}
