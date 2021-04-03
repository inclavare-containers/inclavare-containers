#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#include <sgx_dcap_quoteverify.h>

enclave_quote_err_t sgx_ecdsa_verify_evidence(enclave_quote_ctx_t *ctx,
					      attestation_evidence_t *evidence,
					      uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	enclave_quote_err_t err = -ENCLAVE_QUOTE_ERR_UNKNOWN;
	time_t current_time = 0;
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;
	/* specified defined for trusted veirification based on qve.
	 * sgx_enclave_id_t eid = 0;
	 * sgx_launch_token_t token = { 0 };
	 * sgx_ql_qe_report_info_t qve_report_info;
	 * unsigned char rand_nonce[16] = "59jslk201fgjmm;";
	 * int updated = 0;
	 */

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
		/* Call DCAP quote verify library to get supplemental data size */
		dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
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
		current_time = time(NULL);
		/* Call DCAP quote verify library for quote verification here you can choose 
		 * untrusted' quote verification by specifying parameter '&qve_report_info' as NULL
		 */
		dcap_ret = sgx_qv_verify_quote(pquote, quote_size,
					       NULL,
					       current_time,
					       &collateral_expiration_status,
					       &quote_verification_result,
					       NULL,
					       supplemental_data_size,
					       p_supplemental_data);
		if (dcap_ret == SGX_QL_SUCCESS)
			ETLS_DEBUG("sgx_qv_verify_quote successfully returned\n");
		else {
			ETLS_ERR("sgx_qv_verify_quote():  0x%04x\n", dcap_ret);
			return SGX_ECDSA_ERR_CODE((int)dcap_ret);
		}

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
