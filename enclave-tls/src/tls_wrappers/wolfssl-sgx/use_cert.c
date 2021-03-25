#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl_sgx.h"

tls_wrapper_err_t wolfssl_sgx_use_cert(tls_wrapper_ctx_t *ctx,
				       enclave_tls_cert_info_t *cert_info)
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err;
	sgx_enclave_id_t eid = ctx->tls_private->config.eid;

	ecall_use_cert(eid, &err, ctx, cert_info);

	return err;
}
