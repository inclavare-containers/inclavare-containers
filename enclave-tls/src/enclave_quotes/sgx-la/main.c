/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <enclave-tls/enclave_quote.h>
#include <enclave-tls/log.h>

extern enclave_quote_err_t enclave_quote_register(enclave_quote_opts_t *);
extern enclave_quote_err_t sgx_la_pre_init(void);
extern enclave_quote_err_t sgx_la_init(enclave_quote_ctx_t *,
				       enclave_tls_cert_algo_t algo);
extern enclave_quote_err_t sgx_la_collect_evidence(enclave_quote_ctx_t *,
						   attestation_evidence_t *,
						   enclave_tls_cert_algo_t algo,
						   uint8_t *);
extern enclave_quote_err_t sgx_la_verify_evidence(enclave_quote_ctx_t *,
						  attestation_evidence_t *,
						  uint8_t *);
extern enclave_quote_err_t sgx_la_cleanup(enclave_quote_ctx_t *);

static enclave_quote_opts_t sgx_la_opts = {
	.api_version = ENCLAVE_QUOTE_API_VERSION_DEFAULT,
	.flags = ENCLAVE_QUOTE_FLAGS_DEFAULT,
	.type = "sgx_la",
	.priority = 15,
	.pre_init = sgx_la_pre_init,
	.init = sgx_la_init,
	.collect_evidence = sgx_la_collect_evidence,
	.verify_evidence = sgx_la_verify_evidence,
	.cleanup = sgx_la_cleanup,
};

void __attribute__((constructor))
libenclave_quote_sgx_la_init(void)
{
	ETLS_DEBUG("called\n");

	enclave_quote_err_t err = enclave_quote_register(&sgx_la_opts);
	if (err != ENCLAVE_QUOTE_ERR_NONE)
		ETLS_ERR("failed to register the enclave quote 'sgx_la' %#x\n",
			 err);
}
