#include <enclave-tls/err.h>

#include "internal/core.h"

/* *INDENT-OFF* */
enclave_tls_err_t
etls_enclave_quote_retrieve_certificate_extension(etls_core_context_t *ctx,
						  attestation_evidence_t *evidence,
						  enclave_tls_cert_algo_t algo,
						  uint8_t *hash)
{
	if (!ctx || !(ctx->attester) || !(ctx->attester->opts) ||
	    !(ctx->attester->opts->collect_evidence))
		return -ENCLAVE_TLS_ERR_INVALID;

	return ctx->attester->opts->collect_evidence(ctx->attester, evidence,
						     algo, hash);
}
/* *INDENT-ON* */
