#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>

enclave_quote_err_t nullquote_verify_evidence(enclave_quote_ctx_t *ctx,
					      attestation_evidence_t *evidence,
					      uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	return ENCLAVE_QUOTE_ERR_NONE;
}
