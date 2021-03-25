#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include "internal/core.h"
#include "internal/enclave_quote.h"

/* *INDENT-OFF* */
enclave_tls_err_t etls_core_generate_certificate(etls_core_context_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	if (!ctx || !ctx->tls_wrapper || !ctx->tls_wrapper->opts ||
	    !ctx->crypto_wrapper || !ctx->crypto_wrapper->opts ||
	    !ctx->crypto_wrapper->opts->gen_pubkey_hash ||
	    !ctx->crypto_wrapper->opts->gen_cert)
		return -ENCLAVE_TLS_ERR_INVALID;

	/* Avoid repeated generation of certificates */
	if (ctx->flags & ENCLAVE_TLS_CTX_FLAGS_CERT_CREATED)
		return ENCLAVE_TLS_ERR_NONE;

	unsigned int hash_size;
	/* Check whether the specified algorithm is supported */
	if (ctx->config.cert_algo == ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
		hash_size = SHA256_HASH_SIZE;
	else {
		ETLS_DEBUG("unknown algorithm %d\n", ctx->config.cert_algo);
		return -ENCLAVE_TLS_ERR_UNSUPPORTED_CERT_ALGO;
	}

	/* Genertate new key pair */
	crypto_wrapper_err_t c_err;
	uint8_t privkey_buf[2048];
	unsigned int privkey_len = 0;
	c_err = ctx->crypto_wrapper->opts->gen_privkey(ctx->crypto_wrapper,
						       ctx->config.cert_algo,
						       privkey_buf, &privkey_len);
	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
		return c_err;

	/* Genertate the hash of public key */
	uint8_t hash[hash_size];
	c_err = ctx->crypto_wrapper->opts->gen_pubkey_hash(ctx->crypto_wrapper,
							   ctx->config.cert_algo,
							   hash);
	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
		return c_err;

	/* Collect certificate evidence */
	enclave_tls_cert_info_t cert_info = {
		.subject = {
			.organization = "Inclavare Containers",
			.organization_unit = "Enclave Attestation Architecture",
			.common_name = "Enclave TLS",
		},
	};
	enclave_quote_err_t q_err;
	q_err = ctx->attester->opts->collect_evidence(ctx->attester, &cert_info.evidence,
						      ctx->config.cert_algo, hash);
	if (q_err != ENCLAVE_QUOTE_ERR_NONE)
		return c_err;

	c_err = ctx->crypto_wrapper->opts->gen_cert(ctx->crypto_wrapper, &cert_info);
	if (c_err != CRYPTO_WRAPPER_ERR_NONE)
		return c_err;

	if (privkey_len) {
		tls_wrapper_err_t t_err;

		t_err = ctx->tls_wrapper->opts->use_privkey(ctx->tls_wrapper,
							    privkey_buf,
							    privkey_len);
		if (t_err != TLS_WRAPPER_ERR_NONE)
			return t_err;

		t_err = ctx->tls_wrapper->opts->use_cert(ctx->tls_wrapper, &cert_info);
		if (t_err != TLS_WRAPPER_ERR_NONE)
			return t_err;
	}

	/* Prevent repeated generation of TLS certificates */
	ctx->flags |= ENCLAVE_TLS_CTX_FLAGS_CERT_CREATED;

	return ENCLAVE_TLS_ERR_NONE;
}
/* *INDENT-ON* */
