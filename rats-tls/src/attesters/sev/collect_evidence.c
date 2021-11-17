/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <rats-tls/cert.h>
#include <string.h>
#include "../../verifiers/sev/sevapi.h"

#define KVM_HC_VM_HANDLE 13

/* The API of retrieve_attestation_evidence_size and retrieve_attestation_evidence
 * is defined in libttrpc.so.
 */
extern uint32_t retrieve_attestation_evidence_size(uint32_t guest_handle);
extern sev_evidence_t *retrieve_attestation_evidence(uint32_t guest_handle, uint32_t evidence_size);

static int do_hypercall(unsigned int p1)
{
	long ret = 0;

	asm volatile("vmmcall" : "=a"(ret) : "a"(p1) : "memory");

	return (int)ret;
}

enclave_attester_err_t sev_collect_evidence(enclave_attester_ctx_t *ctx,
					    attestation_evidence_t *evidence,
					    rats_tls_cert_algo_t algo, uint8_t *hash,
					    __attribute__((unused)) uint32_t hash_len)
{
	RTLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	/* Get guest firmware handle by KVM_HC_VM_HANDLE hypercall */
	uint32_t guest_handle = do_hypercall(KVM_HC_VM_HANDLE);
	if (guest_handle <= 0) {
		RTLS_ERR("failed to get guest handle, invalid guest_handle %d\n", guest_handle);
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}
	RTLS_DEBUG("guest firmware handle is %d\n", guest_handle);

	/* Send retrieve_attestation_evidence request to AEB service through vsock.
	 * AEB service returns attestation evidence to sev attester.
	 * The implement of retrieve_attestation_evidence_size, retrieve_attestation_evidence
	 * is defined in libttrpc.so.
	 */
	uint32_t evidence_size = retrieve_attestation_evidence_size(guest_handle);
	if (evidence_size != sizeof(sev_evidence_t)) {
		RTLS_ERR("failed to retrieve attestation evidence size, invalid size %d\n",
			 evidence_size);
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	sev_evidence_t *s_evidence = retrieve_attestation_evidence(guest_handle, evidence_size);
	if (!s_evidence) {
		RTLS_ERR("failed to retrieve attestation_evidence\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	RTLS_DEBUG("Succeed to retrieve the sev evidence!\n");

	sev_attestation_evidence_t *sev_report = &evidence->sev;
	memcpy(sev_report->report, s_evidence, sizeof(*s_evidence));
	sev_report->report_len = evidence_size;

	snprintf(evidence->type, sizeof(evidence->type), "sev");

	RTLS_DEBUG("ctx %p, evidence %p, report_len %d\n", ctx, evidence, evidence->sev.report_len);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
