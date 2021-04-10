#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>
#include <stddef.h>
#include <sgx_uae_service.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#include <sgx_dcap_quoteverify.h>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_ql_lib_common.h>
#include <sgx_error.h>
#include "sgx_ecdsa.h"
#include "sgx_stub_u.h"

enclave_quote_err_t sgx_ecdsa_collect_evidence(enclave_quote_ctx_t *ctx,
					       attestation_evidence_t *evidence,
					       enclave_tls_cert_algo_t algo,
					       uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence,
		   algo, hash);

	sgx_ecdsa_ctx_t *ecdsa_ctx = (sgx_ecdsa_ctx_t *)ctx->quote_private;

	sgx_report_t app_report;
	sgx_status_t generate_evidence_ret;
	sgx_status_t status = ecall_generate_evidence(ecdsa_ctx->eid, &generate_evidence_ret,
						      hash, &app_report);
	if (status != SGX_SUCCESS || generate_evidence_ret != SGX_SUCCESS) {
		ETLS_ERR("ecall_generate_evidence() %#x\n", generate_evidence_ret);
		return SGX_ECDSA_ERR_CODE((int)generate_evidence_ret);
	}

	strcpy(evidence->type, "sgx_ecdsa");

	uint32_t quote_size = 0;
	quote3_error_t qe3_ret = sgx_qe_get_quote_size(&quote_size);
	if (SGX_QL_SUCCESS != qe3_ret) {
		ETLS_ERR("sgx_qe_get_quote_size(): 0x%04x\n", qe3_ret);
		return SGX_ECDSA_ERR_CODE((int)qe3_ret);
	}

	qe3_ret = sgx_qe_get_quote(&app_report, quote_size, evidence->ecdsa.quote);
	if (SGX_QL_SUCCESS != qe3_ret) {
		ETLS_ERR("sgx_qe_get_quote(): 0x%04x\n", qe3_ret);
		return SGX_ECDSA_ERR_CODE((int)qe3_ret);
	}

	evidence->ecdsa.quote_len = quote_size;

	return ENCLAVE_QUOTE_ERR_NONE;
}
