#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>
#include "sgx_ecdsa.h"

/* *INDENT-OFF* */
enclave_quote_err_t sgx_ecdsa_init(enclave_quote_ctx_t *ctx,
				   enclave_tls_cert_algo_t algo)
{
	ETLS_DEBUG("ctx %p, algo %d\n", ctx, algo);

	sgx_ecdsa_ctx_t *ecdsa_ctx = calloc(1, sizeof(*ecdsa_ctx));
	if (!ecdsa_ctx)
		return -ENCLAVE_QUOTE_ERR_NO_MEM;

	ecdsa_ctx->eid = ctx->eid;

	ctx->quote_private = ecdsa_ctx;

	return ENCLAVE_QUOTE_ERR_NONE;
}
/* *INDENT-ON* */
