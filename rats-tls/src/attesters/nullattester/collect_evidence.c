/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>

enclave_attester_err_t nullattester_collect_evidence(enclave_attester_ctx_t *ctx,
						     attestation_evidence_t *evidence,
						     rats_tls_cert_algo_t algo, uint8_t *hash,
						     __attribute__((unused)) uint32_t hash_len)
{
	RTLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
