#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/err.h>

#include "internal/tls_wrapper.h"
#include "internal/enclave_quote.h"

tls_wrapper_err_t tls_wrapper_verify_certificate_extension(tls_wrapper_ctx_t *tls_ctx,
							   attestation_evidence_t *evidence,
							   uint8_t *hash)
{
	ETLS_DEBUG("tls_wrapper_verify_certificate_extension() called with evidence type: '%s'\n", evidence->type);

	for (unsigned int i = 0; i < registerd_enclave_quote_nums; ++i) {
		enclave_quote_ctx_t *quote_ctx = enclave_quotes_ctx[i];

		if (strcmp(evidence->type, quote_ctx->opts->type))
			continue;

		if (!quote_ctx || !(quote_ctx->opts) ||
		    !(quote_ctx->opts->verify_evidence))
			return -TLS_WRAPPER_ERR_INVALID;

		//quote_ctx->quote_private = tls_ctx->tls_private;
		enclave_quote_err_t err =
			quote_ctx->opts->verify_evidence(quote_ctx, evidence,
							 hash);
		if (err != ENCLAVE_QUOTE_ERR_NONE) {
			ETLS_ERR("ERROR: failed to verify_evidence()\n");
			return err;
		}
	}

	return TLS_WRAPPER_ERR_NONE;
}
