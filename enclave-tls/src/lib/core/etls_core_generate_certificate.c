#include <enclave-tls/log.h>
#include <enclave-tls/err.h>

#include "internal/core.h"
#include "internal/enclave_quote.h"

/* *INDENT-OFF* */
enclave_tls_err_t etls_core_generate_certificate(etls_core_context_t *ctx)
{
	ETLS_DEBUG("etls_core_generate_certificate() is called\n");

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	if (!(ctx) || !(ctx->tls_wrapper) || !(ctx->tls_wrapper->opts) ||
	    !(ctx->tls_wrapper->opts->gen_pubkey_hash) ||
	    !(ctx->tls_wrapper->opts->gen_cert))
		return -ENCLAVE_TLS_ERR_INVALID;

	/* Avoid repeated generation of certificates */
	if (ctx->flags & ENCLAVE_TLS_CTX_FLAGS_CERT_CREATED)
		return ENCLAVE_TLS_ERR_NONE;

	unsigned int hash_size;
	/* Check whether the specified algorithm is supported */
	if (ctx->config.cert_algo == ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
		hash_size = SHA256_HASH_SIZE;
	else
		return -ENCLAVE_TLS_ERR_UNSUPPORTED_CERT_ALGO;

	/* Genertate new hash and key pair */
	uint8_t hash[hash_size];
	err = ctx->tls_wrapper->opts->gen_pubkey_hash(ctx->tls_wrapper,
						      ctx->config.cert_algo,
						      hash);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("ERROR: gen_pubkey_hash()\n");
		return err;
	}

	/* Collect certificate evidence */
	tls_wrapper_cert_info_t cert_info = {
		.subject = {
			    .organization = "Inclavare Containers",
			    .organization_unit =
			    "Enclave Attestation Architecture",
			    .common_name = "Enclave TLS",
			    },
	};
	err = etls_enclave_quote_retrieve_certificate_extension(ctx,
								&cert_info.evidence,
								ctx->
								config.cert_algo,
								hash);
	if (err != ENCLAVE_QUOTE_ERR_NONE) {
		ETLS_ERR("ERROR: etls_enclave_quote_retrieve_certificate_extension()\n");
		return err;
	}

	/* Generate TLS certificate */
	err = ctx->tls_wrapper->opts->gen_cert(ctx->tls_wrapper, &cert_info);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("ERROR: gen_cert()\n");
		return err;
	}

	/* Prevent repeated generation of TLS certificates */
	ctx->flags |= ENCLAVE_TLS_CTX_FLAGS_CERT_CREATED;

	return ENCLAVE_TLS_ERR_NONE;
}
/* *INDENT-ON* */
