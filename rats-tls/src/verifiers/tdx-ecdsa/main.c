/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include <stdio.h>

extern enclave_verifier_err_t
enclave_verifier_register(enclave_verifier_opts_t *opts);
extern enclave_verifier_err_t tdx_ecdsa_verifier_pre_init(void);
extern enclave_verifier_err_t tdx_ecdsa_verifier_init(enclave_verifier_ctx_t *ctx,
						      rats_tls_cert_algo_t algo);
extern enclave_verifier_err_t
tdx_ecdsa_verify_evidence(enclave_verifier_ctx_t *ctx,
			  attestation_evidence_t *evidence, uint8_t *hash,
			  uint32_t hash_len);
extern enclave_verifier_err_t tdx_ecdsa_verifier_cleanup(enclave_verifier_ctx_t *ctx);

static enclave_verifier_opts_t tdx_ecdsa_verifier_opts = {
	.api_version = ENCLAVE_VERIFIER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_VERIFIER_OPTS_FLAGS_TDX,
	.name = "tdx_ecdsa",
	.priority = 42,
	.pre_init = tdx_ecdsa_verifier_pre_init,
	.init = tdx_ecdsa_verifier_init,
	.verify_evidence = tdx_ecdsa_verify_evidence,
	.cleanup = tdx_ecdsa_verifier_cleanup,
};

void __attribute__((constructor)) libverifier_tdx_ecdsa_init(void)
{
	RTLS_DEBUG("called\n");

	enclave_verifier_err_t err = enclave_verifier_register(&tdx_ecdsa_verifier_opts);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		RTLS_ERR("failed to register the enclave verifier 'tdx_ecdsa' %#x\n", err);
}
