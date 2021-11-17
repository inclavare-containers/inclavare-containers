/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include "utils.h"
#include "sevcert.h"

enclave_verifier_err_t sev_verify_evidence(enclave_verifier_ctx_t *ctx,
					   attestation_evidence_t *evidence, uint8_t *hash,
					   uint32_t hash_len)
{
	RTLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;

	/* SEV/SEV-ES do NOT support self-defined user_data, which is supported in SEV SNP */

	sev_evidence_t *evi = (sev_evidence_t *)(evidence->sev.report);
	sev_cert *cek = &evi->cek_cert;
	sev_cert *pek = &evi->pek_cert;
	sev_cert *oca = &evi->oca_cert;
	sev_attestation_report *report = &evi->attestation_report;

	/*  Generate ask and ark cert */
	amd_cert ask_cert;
	amd_cert ark_cert;
	SEV_ERROR_CODE cmd_ret = sev_load_ask_cert(&ask_cert, &ark_cert);
	if (cmd_ret != STATUS_SUCCESS) {
		RTLS_ERR("failed to load ASK cert %x\n", cmd_ret);
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	/* Verify ARK cert with ARK */
	cmd_ret = amd_cert_validate_ark(&ark_cert);
	if (cmd_ret != STATUS_SUCCESS) {
		RTLS_ERR("failed to verify ARK cert %x\n", cmd_ret);
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}
	RTLS_INFO("verify ARK cert success\n");

	/* Verify ASK cert with ARK */
	cmd_ret = amd_cert_validate_ask(&ask_cert, &ark_cert);
	if (cmd_ret != STATUS_SUCCESS) {
		RTLS_ERR("failed to verify ASK cert %x\n", cmd_ret);
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}
	RTLS_INFO("verify ASK cert success\n");

	/* Verify CEK cert with ASK */
	sev_cert ask_pubkey;
	cmd_ret = amd_cert_export_pub_key(&ask_cert, &ask_pubkey);
	if (cmd_ret != STATUS_SUCCESS) {
		RTLS_ERR("failed to export pub key form ask %x\n", cmd_ret);
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	cmd_ret = verify_sev_cert(cek, &ask_pubkey, NULL);
	if (cmd_ret != STATUS_SUCCESS) {
		RTLS_ERR("failed to verify CEK cert\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}
	RTLS_INFO("verify CEK cert success\n");

	/* Verify PEK cert with CEK and OCA */
	if (verify_sev_cert(pek, oca, cek) != STATUS_SUCCESS) {
		RTLS_ERR("failed to verify PEK cert\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}
	RTLS_INFO("verify PEK cert success\n");

	/* Verify attestation report with PEK */
	if (validate_attestation(pek, report)) {
		RTLS_ERR("failed to verify attestation report\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}
	RTLS_INFO("verify attestation report success\n");

	err = ENCLAVE_VERIFIER_ERR_NONE;

	return err;
}
