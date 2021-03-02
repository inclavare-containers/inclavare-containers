#include <string.h>

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

/* *INDENT-OFF* */
tls_wrapper_err_t null_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	ETLS_DEBUG("tls_wrapper_null negotiate() called\n");

	if (!(ctx->conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER) ||
	    ((ctx->conf_flags & ENCLAVE_TLS_CONF_FLAGS_MUTUAL) &&
	     (ctx->conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER))) {
		tls_wrapper_err_t err;
		uint8_t hash[SHA256_HASH_SIZE];
		attestation_evidence_t evidence;

		/* There is no evidence in tls_wrapper_null */
		strcpy(evidence.type, "null");

		err = tls_wrapper_verify_certificate_extension(ctx, &evidence,
							       hash);
		if (err != TLS_WRAPPER_ERR_NONE) {
			ETLS_ERR("ERROR: failed to verify certificate extension\n");
			return err;
		}
	}
	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
