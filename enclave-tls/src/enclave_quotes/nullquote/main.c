#include <stdio.h>
#include <enclave-tls/enclave_quote.h>
#include <enclave-tls/log.h>

extern enclave_quote_err_t enclave_quote_register(enclave_quote_opts_t *);
extern enclave_quote_err_t nullquote_pre_init(void);
extern enclave_quote_err_t nullquote_init(enclave_quote_ctx_t *,
					  enclave_tls_cert_algo_t algo);
//extern enclave_quote_err_t nullquote_extend_cert(enclave_quote_ctx_t *ctx,
//					    const enclave_tls_cert_info_t *cert_info);
extern enclave_quote_err_t nullquote_collect_evidence(enclave_quote_ctx_t *,
						      attestation_evidence_t *,
						      enclave_tls_cert_algo_t algo,
						      uint8_t *);
extern enclave_quote_err_t nullquote_verify_evidence(enclave_quote_ctx_t *,
						     attestation_evidence_t *, uint8_t *);
extern enclave_quote_err_t nullquote_cleanup(enclave_quote_ctx_t *);

static enclave_quote_opts_t nullquote_opts = {
	.version = ENCLAVE_QUOTE_API_VERSION_DEFAULT,
	.flags = ENCLAVE_QUOTE_FLAGS_DEFAULT,
	.type = "nullquote",
	.priority = 0,
	.pre_init = nullquote_pre_init,
	.init = nullquote_init,
	//.extend_cert = nullquote_extend_cert,
	.collect_evidence = nullquote_collect_evidence,
	.verify_evidence = nullquote_verify_evidence,
	.cleanup = nullquote_cleanup,
};

/* *INDENT-OFF* */
void __attribute__((constructor))
libenclave_quote_nullquote_init(void)
{
	ETLS_DEBUG("called\n");

	enclave_quote_err_t err = enclave_quote_register(&nullquote_opts);
	if (err != ENCLAVE_QUOTE_ERR_NONE)
		ETLS_FATAL("failed to register the enclave quote 'nullquote'\n");
}
/* *INDENT-ON* */
