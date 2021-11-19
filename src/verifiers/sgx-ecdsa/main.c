/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <rats-tls/verifier.h>
#include <rats-tls/log.h>

extern enclave_verifier_err_t enclave_verifier_register(enclave_verifier_opts_t *opts);
extern enclave_verifier_err_t sgx_ecdsa_verifier_pre_init(void);
extern enclave_verifier_err_t sgx_ecdsa_verifier_init(enclave_verifier_ctx_t *ctx,
						      rats_tls_cert_algo_t algo);
extern enclave_verifier_err_t sgx_ecdsa_verify_evidence(enclave_verifier_ctx_t *ctx,
							attestation_evidence_t *evidence,
							uint8_t *hash, uint32_t hash_len);
extern enclave_verifier_err_t sgx_ecdsa_verifier_cleanup(enclave_verifier_ctx_t *ctx);

static enclave_verifier_opts_t sgx_ecdsa_verifier_opts = {
	.api_version = ENCLAVE_VERIFIER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_VERIFIER_FLAGS_DEFAULT | ENCLAVE_VERIFIER_OPTS_FLAGS_SGX2_ENCLAVE,
	.name = "sgx_ecdsa",
	.priority = 52,
	.pre_init = sgx_ecdsa_verifier_pre_init,
	.init = sgx_ecdsa_verifier_init,
	.verify_evidence = sgx_ecdsa_verify_evidence,
	.cleanup = sgx_ecdsa_verifier_cleanup,
};

#ifdef SGX
void libverifier_sgx_ecdsa_init(void)
#else
void __attribute__((constructor)) libverifier_sgx_ecdsa_init(void)
#endif
{
	RTLS_DEBUG("called\n");

	enclave_verifier_err_t err = enclave_verifier_register(&sgx_ecdsa_verifier_opts);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		RTLS_DEBUG("failed to register the enclave verifier 'sgx_ecdsa' %#x\n", err);
}
