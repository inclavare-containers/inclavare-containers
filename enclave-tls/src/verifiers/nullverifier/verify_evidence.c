/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/verifier.h>

enclave_verifier_err_t nullverifier_verify_evidence(enclave_verifier_ctx_t *ctx,
						    attestation_evidence_t *evidence, uint8_t *hash,
						    __attribute__((unused)) unsigned int hash_len)
{
	ETLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	return ENCLAVE_VERIFIER_ERR_NONE;
}
