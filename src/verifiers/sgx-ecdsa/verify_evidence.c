/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/verifier.h>
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#include "sgx_ecdsa.h"
#ifdef SGX
#include <etls_t.h>
#elif defined(OCCLUM)
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "quote_verification.h"
#else
#include <sgx_dcap_quoteverify.h>
#include <sgx_dcap_ql_wrapper.h>
// clang-format on

enclave_verifier_err_t ecdsa_verify_evidence(__attribute__((unused)) enclave_verifier_ctx_t *ctx,
					     const char *name, attestation_evidence_t *evidence,
					     __attribute__((unused)) uint32_t evidence_len,
					     uint8_t *hash, uint32_t hash_len)
{
	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;
	time_t current_time = 0;
	sgx_isv_svn_t qve_isvsvn_threshold = 3;
	sgx_status_t sgx_ret = SGX_SUCCESS;
	quote3_error_t verify_qveid_ret = SGX_QL_ERROR_UNEXPECTED;
	quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
	sgx_ql_qe_report_info_t *qve_report_info = NULL;
	uint8_t rand_nonce[16];

	sgx_quote3_t *pquote = (sgx_quote3_t *)malloc(8192);
	if (!pquote) {
		ETLS_ERR("failed to malloc sgx quote3 data space.\n");
		return -ENCLAVE_VERIFIER_ERR_NO_MEM;
	}

	memcpy(pquote, evidence->ecdsa.quote, evidence->ecdsa.quote_len);

	uint32_t quote_size = (uint32_t)sizeof(sgx_quote3_t) + pquote->signature_data_len;
	ETLS_DEBUG("quote size is %d, quote signature_data_len is %d\n", quote_size,
		   pquote->signature_data_len);

	/* First verify the hash value */
	if (memcmp(hash, pquote->report_body.report_data.d, hash_len) != 0) {
		ETLS_ERR("unmatched hash value in evidence.\n");
		err = -ENCLAVE_VERIFIER_ERR_INVALID;
		goto errout;
	}

	dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
	if (dcap_ret == SGX_QL_SUCCESS) {
		ETLS_INFO("sgx qv gets quote supplemental data size successfully.\n");
		p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
		if (!p_supplemental_data) {
			ETLS_ERR("failed to malloc supplemental data space.\n");
			err = -ENCLAVE_VERIFIER_ERR_NO_MEM;
			goto errout;
		}
	} else {
		ETLS_ERR("failed to get quote supplemental data size by sgx qv: %04x\n", dcap_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
		goto errout;
	}

	current_time = time(NULL);

	dcap_ret = sgx_qv_verify_quote(evidence->ecdsa.quote, (uint32_t)quote_size, NULL,
				       current_time, &collateral_expiration_status,
				       &quote_verification_result, qve_report_info,
				       supplemental_data_size, p_supplemental_data);
	if (dcap_ret == SGX_QL_SUCCESS)
		ETLS_INFO("sgx qv verifies quote successfully.\n");
	else {
		ETLS_ERR("failed to verify quote by sgx qv: %04x\n", dcap_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
		goto errret;
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
		ETLS_INFO("verification completed successfully.\n");
		err = ENCLAVE_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		ETLS_WARN("verification completed with Non-terminal result: %x\n",
			   quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		ETLS_WARN("verification completed with Terminal result: %x\n",
			   quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	}

errret:
	free(p_supplemental_data);
errout:
	free(qve_report_info);
	free(pquote);

	return err;
}
#endif

enclave_verifier_err_t sgx_ecdsa_verify_evidence(enclave_verifier_ctx_t *ctx,
						 attestation_evidence_t *evidence, uint8_t *hash,
						 __attribute__((unused)) uint32_t hash_len)
{
	ETLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_verifier_err_t err = -ENCLAVE_VERIFIER_ERR_UNKNOWN;
#ifdef OCCLUM
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;

	int sgx_fd = open("/dev/sgx", O_RDONLY);
	if (sgx_fd < 0) {
		ETLS_ERR("failed to open /dev/sgx\n");
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	if (ioctl(sgx_fd, SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE, &supplemental_data_size) < 0) {
		ETLS_ERR("failed to ioctl get supplemental data size: %s\n", strerror(errno));
		close(sgx_fd);
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
	if (!p_supplemental_data) {
		close(sgx_fd);
		return -ENCLAVE_VERIFIER_ERR_NO_MEM;
	}

	memset(p_supplemental_data, 0, supplemental_data_size);

	sgxioc_ver_dcap_quote_arg_t ver_quote_arg = {
		.quote_buf = evidence->ecdsa.quote,
		.quote_size = evidence->ecdsa.quote_len,
		.collateral_expiration_status = &collateral_expiration_status,
		.quote_verification_result = &quote_verification_result,
		.supplemental_data_size = supplemental_data_size,
		.supplemental_data = p_supplemental_data
	};

	if (ioctl(sgx_fd, SGXIOC_VER_DCAP_QUOTE, &ver_quote_arg) < 0) {
		ETLS_ERR("failed to ioctl verify quote: %s\n", strerror(errno));
		close(sgx_fd);
		return -ENCLAVE_VERIFIER_ERR_INVALID;
	}

	close(sgx_fd);

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
		ETLS_INFO("verification completed successfully.\n");
		err = ENCLAVE_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		ETLS_WARN("verification completed with Non-terminal result: %x\n",
			  quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		ETLS_ERR("verification completed with Terminal result: %x\n",
			 quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	}
#elif defined(SGX)
	sgx_ecdsa_ctx_t *ecdsa_ctx = (sgx_ecdsa_ctx_t *)ctx->verifier_private;
	sgx_enclave_id_t eid = (sgx_enclave_id_t)ecdsa_ctx->eid;
	ocall_ecdsa_verify_evidence(&err, ctx, eid, ctx->opts->name, evidence,
				    sizeof(attestation_evidence_t), hash, hash_len);
#else
	err = ecdsa_verify_evidence(ctx, ctx->opts->name, evidence, sizeof(attestation_evidence_t),
				    hash, hash_len);
	if (err != ENCLAVE_VERIFIER_ERR_NONE)
		ETLS_ERR("failed to verify ecdsa\n");
#endif

	return err;
}
