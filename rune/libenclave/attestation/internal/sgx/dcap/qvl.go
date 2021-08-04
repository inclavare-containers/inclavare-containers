package dcap // import "github.com/inclavare-containers/rune/libenclave/attestation/internal/sgx/dcap"

/*
#cgo LDFLAGS: -lsgx_dcap_quoteverify -lsgx_urts

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sgx_dcap_quoteverify.h>

#define SGX_ECDSA_MIN_QUOTE_SIZE 1020

int ecdsa_quote_verification(uint8_t *quote, uint32_t quote_size, bool use_qve)
{
	int ret = 0;
	time_t current_time = 0;
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	sgx_ql_qe_report_info_t qve_report_info;
	uint32_t collateral_expiration_status = 1;
	int updated = 0;
	quote3_error_t verify_qveid_ret = SGX_QL_ERROR_UNEXPECTED;

	if (!quote || quote_size < SGX_ECDSA_MIN_QUOTE_SIZE) {
		return SGX_QL_ERROR_INVALID_PARAMETER;
	}

	// Trusted quote verification
	if (use_qve) {
		fprintf(stderr, "Unsupport Quote Verifier Enclave.\n");
		return -1;
	}
	// Untrusted quote verification
	else {
		// call DCAP quote verify library to get supplemental data size
		dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
		if (dcap_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
			fprintf(stdout, "Info: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
			p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
		}
		else {
			fprintf(stderr, "Error: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", dcap_ret);
			supplemental_data_size = 0;
		}

		// set current time. This is only for sample purposes, in production mode a trusted time should be used.
		current_time = time(NULL);

		// call DCAP quote verify library for quote verification
		// here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
		// if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
		// if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
		dcap_ret = sgx_qv_verify_quote(
			quote, quote_size,
			NULL,
			current_time,
			&collateral_expiration_status,
			&quote_verification_result,
			NULL,
			supplemental_data_size,
			p_supplemental_data);
		if (dcap_ret == SGX_QL_SUCCESS) {
			fprintf(stdout, "Info: App: sgx_qv_verify_quote successfully returned.\n");
		}
		else {
			fprintf(stderr, "Error: App: sgx_qv_verify_quote failed: 0x%04x\n", dcap_ret);
		}

		// check verification result
		switch (quote_verification_result) {
		case SGX_QL_QV_RESULT_OK:
			fprintf(stdout, "Info: App: Verification completed successfully.\n");
			ret = 0;
			break;
		case SGX_QL_QV_RESULT_CONFIG_NEEDED:
		case SGX_QL_QV_RESULT_OUT_OF_DATE:
		case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
		case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
		case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
			fprintf(stdout, "Warning: App: Verification completed with Non-terminal result: %x\n", quote_verification_result);
			ret = 1;
			break;
		case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
		case SGX_QL_QV_RESULT_REVOKED:
		case SGX_QL_QV_RESULT_UNSPECIFIED:
		default:
			fprintf(stderr, "Error: App: Verification completed with Terminal result: %x\n", quote_verification_result);
			ret = -1;
			break;
		}
	}

	return ret;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func VerifyEcdsaQuote(quote []byte) error {
	ret := C.ecdsa_quote_verification((*C.uint8_t)(unsafe.Pointer(&quote[0])),
		C.uint32_t(len(quote)),
		C.bool(false))
	if ret != 0 {
		return fmt.Errorf("C.ecdsa_quote_verification failed, return %d\n", ret)
	}

	return nil
}
