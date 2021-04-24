/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#include <sgx_dcap_quoteverify.h>
#ifdef OCCLUM
  #include <string.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <sys/ioctl.h>
  #include <errno.h>
  #include "quote_verification.h"
#endif

enclave_quote_err_t sgx_ecdsa_verify_evidence(enclave_quote_ctx_t *ctx,
					      attestation_evidence_t *evidence,
					      uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_quote_err_t err = -ENCLAVE_QUOTE_ERR_UNKNOWN;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;

	sgx_quote3_t *pquote = (sgx_quote3_t *)malloc(8192);
	if (!pquote)
		return -ENCLAVE_QUOTE_ERR_NO_MEM;

	memcpy(pquote, evidence->ecdsa.quote, evidence->ecdsa.quote_len);

	uint32_t quote_size = 436 + pquote->signature_data_len;
	ETLS_DEBUG("quote size is %d, quote signature_data_len is %d\n",
		   quote_size, pquote->signature_data_len);

	/* 1 means trusted verify methond by QvE, 0 means verify by untructed QPL */
	bool verify_by_qve = 0;
	if (verify_by_qve) {
		/* In current stage, some machine is for pre-prouction and verifying
		 * by QvE is not supported
		 */
		ETLS_DEBUG("verify by trusted model.\n");
		return ENCLAVE_QUOTE_ERR_NONE;
	} else {
#ifdef OCCLUM
		int sgx_fd = open("/dev/sgx", O_RDONLY);
		if (sgx_fd < 0) {
			ETLS_ERR("failed to open /dev/sgx\n");
			return -ENCLAVE_QUOTE_ERR_INVALID;
		}

		if (ioctl(sgx_fd, SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE, &supplemental_data_size) < 0) {
			ETLS_ERR("failed to ioctl get supplemental data size: %s\n", strerror(errno));
			close(sgx_fd);
			return -ENCLAVE_QUOTE_ERR_INVALID;
		}

		p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
		if (!p_supplemental_data) {
			close(sgx_fd);
			return -ENCLAVE_QUOTE_ERR_NO_MEM;
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
			return -ENCLAVE_QUOTE_ERR_INVALID;
		}

		close(sgx_fd);
#else
		/* Call DCAP quote verify library to get supplemental data size */
		quote3_error_t dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
		if (dcap_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
			ETLS_DEBUG("sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
			p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
			if (!p_supplemental_data)
				return -ENCLAVE_QUOTE_ERR_NO_MEM;
		} else {
			ETLS_ERR("sgx_qv_get_quote_supplemental_data_size(): 0x%04x\n", dcap_ret);
			supplemental_data_size = 0;
			return SGX_ECDSA_ERR_CODE((int)dcap_ret);
		}

		/* Set current time. This is only for sample purposes, in production mode 
		 * a trusted time should be used.
		 */
		time_t current_time = time(NULL);
		/* Call DCAP quote verify library for quote verification here you can choose 
		 * untrusted' quote verification by specifying parameter '&qve_report_info' as NULL
		 */
		dcap_ret = sgx_qv_verify_quote(evidence->ecdsa.quote, quote_size,
					       NULL, current_time,
					       &collateral_expiration_status,
					       &quote_verification_result,
					       NULL, supplemental_data_size,
					       p_supplemental_data);
		if (dcap_ret == SGX_QL_SUCCESS)
			ETLS_DEBUG("sgx_qv_verify_quote successfully returned\n");
		else {
			ETLS_ERR("failed to call sgx_qv_verify_quote %#04x\n", dcap_ret);
			return SGX_ECDSA_ERR_CODE((int)dcap_ret);
		}
#endif
		/* Check verification result */
		switch (quote_verification_result) {
		case SGX_QL_QV_RESULT_OK:
			ETLS_DEBUG("Verification completed successfully.\n");
			err = ENCLAVE_QUOTE_ERR_NONE;
			break;
		case SGX_QL_QV_RESULT_CONFIG_NEEDED:
		case SGX_QL_QV_RESULT_OUT_OF_DATE:
		case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
		case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
		case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
			ETLS_WARN("Verification completed with Non-terminal result: %x\n", quote_verification_result);
			err = SGX_ECDSA_ERR_CODE((int)quote_verification_result);
			break;
		case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
		case SGX_QL_QV_RESULT_REVOKED:
		case SGX_QL_QV_RESULT_UNSPECIFIED:
		default:
			ETLS_ERR("Verification completed with Terminal result: %x\n", quote_verification_result);
			err = SGX_ECDSA_ERR_CODE((int)quote_verification_result);
			break;
		}

		free(p_supplemental_data);
		free(pquote);
	}

	return err;
}
