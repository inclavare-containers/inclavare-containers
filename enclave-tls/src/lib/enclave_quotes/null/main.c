#include <stdio.h>
#include <enclave-tls/enclave_quote.h>
#include <enclave-tls/log.h>

extern enclave_quote_err_t enclave_quote_register(enclave_quote_opts_t *);
extern enclave_quote_err_t null_pre_init(void);
extern enclave_quote_err_t null_init(enclave_quote_ctx_t *,
				     enclave_tls_cert_algo_t algo);
extern enclave_quote_err_t null_collect_evidence(enclave_quote_ctx_t *,
						 attestation_evidence_t *,
						 enclave_tls_cert_algo_t algo,
						 uint8_t *);
extern enclave_quote_err_t null_verify_evidence(enclave_quote_ctx_t *,
						attestation_evidence_t *, uint8_t *);
extern enclave_quote_err_t null_cleanup(enclave_quote_ctx_t *);

static enclave_quote_opts_t opts_test = {
	.version = ENCLAVE_QUOTE_API_VERSION_DEFAULT,
	.flags = ENCLAVE_QUOTE_FLAGS_DEFAULT,
	.type = "null",
	.priority = 0,
	.pre_init = null_pre_init,
	.init = null_init,
	.collect_evidence = null_collect_evidence,
	.verify_evidence = null_verify_evidence,
	.cleanup = null_cleanup,
};

/* *INDENT-OFF* */
void __attribute__((constructor))
libenclave_quote_null_init(void)
{
	ETLS_DEBUG("The constructor of libenclave_quote_null.so is called\n");

	enclave_quote_err_t err = enclave_quote_register(&opts_test);
	if (err != ENCLAVE_QUOTE_ERR_NONE) {
		ETLS_ERR("ERROR: failed to register enclave quote \"NULL\"\n");
	}
}
/* *INDENT-ON* */
