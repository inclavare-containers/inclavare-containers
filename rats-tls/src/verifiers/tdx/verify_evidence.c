/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include <sgx_quote_3.h>
#include <sgx_dcap_quoteverify.h>
#include "tdx.h"

enclave_verifier_err_t ecdsa_verify_evidence(__attribute__((unused)) enclave_verifier_ctx_t *ctx,
					     const char *name, attestation_evidence_t *evidence,
					     __attribute__((unused)) uint32_t evidence_len,
					     uint8_t *hash, uint32_t hash_len)
{
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;

	sgx_quote3_t *pquote = (sgx_quote3_t *)malloc(sizeof(evidence->tdx.quote));
	if (!pquote) {
		RTLS_ERR("failed to malloc sgx quote3 data space.\n");
		return -ENCLAVE_VERIFIER_ERR_NO_MEM;
	}

	/* First verify the hash value */
	memcpy(pquote, evidence->tdx.quote, evidence->tdx.quote_len);
	if (memcmp(hash, pquote->report_body.report_data.d, hash_len) != 0) {
		RTLS_ERR("unmatched hash value in evidence.\n");
		err = -ENCLAVE_VERIFIER_ERR_INVALID;
		goto errout;
	}

	/* Call DCAP quote verify library to get supplemental data size */
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	quote3_error_t dcap_ret = tdx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
	if (dcap_ret == SGX_QL_SUCCESS &&
	    supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
		RTLS_INFO("tdx qv gets quote supplemental data size successfully.\n");
		p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
		if (!p_supplemental_data) {
			RTLS_ERR("failed to malloc supplemental data space.\n");
			err = -ENCLAVE_VERIFIER_ERR_NO_MEM;
			goto errout;
		}
	} else {
		RTLS_ERR("failed to get quote supplemental data size by sgx qv: %04x\n", dcap_ret);
		err = (int)dcap_ret;
		goto errout;
	}

	/* Call DCAP quote verify library for quote verification */
	time_t current_time = time(NULL);
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;
	dcap_ret = tdx_qv_verify_quote(evidence->tdx.quote, (uint32_t)(evidence->tdx.quote_len),
				       NULL, current_time, &collateral_expiration_status,
				       &quote_verification_result, NULL, supplemental_data_size,
				       p_supplemental_data);
	if (dcap_ret == SGX_QL_SUCCESS) {
		RTLS_INFO("tdx qv verifies quote successfully.\n");
	} else {
		RTLS_ERR("failed to verify quote by tdx qv: %04x\n", dcap_ret);
		err = (int)quote_verification_result;
		goto errret;
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
		RTLS_INFO("verification completed successfully.\n");
		err = ENCLAVE_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		RTLS_WARN("verification completed with Non-terminal result: %x\n",
			  quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		RTLS_WARN("verification completed with Terminal result: %x\n",
			  quote_verification_result);
		err = (int)quote_verification_result;
		break;
	}
errret:
	free(p_supplemental_data);
errout:
	free(pquote);

	return err;
}

enclave_verifier_err_t tdx_verify_evidence(enclave_verifier_ctx_t *ctx,
					   attestation_evidence_t *evidence, uint8_t *hash,
					   __attribute__((unused)) uint32_t hash_len)
{
	RTLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
	err = ecdsa_verify_evidence(ctx, ctx->opts->name, evidence, sizeof(attestation_evidence_t),
				    hash, hash_len);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		RTLS_ERR("failed to verify ecdsa\n");

	return err;
}
