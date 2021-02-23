#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sgx_uae_service.h>
#include <sgx_urts.h>
#include <sgx_report.h>

#ifdef RATLS_ECDSA
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_default_quote_provider.h>
#include <sgx_ql_lib_common.h>
#include <sgx_error.h>
#include <sgx_quote_3.h>
#endif

#include <ra.h>
#include <ra-attester.h>
#include <ias-ra.h>

#ifdef RATLS_ECDSA
void ecdsa_get_quote(sgx_report_t* report, uint8_t* quote, uint32_t* quote_len)
{
	uint32_t quote_size = 0;

	quote3_error_t qe3_ret = sgx_qe_get_quote_size(&quote_size);
	if (SGX_QL_SUCCESS != qe3_ret) {
		fprintf(stderr, "Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
		return;
	}

	qe3_ret = sgx_qe_get_quote(report,
			quote_size,
			quote);
	if (SGX_QL_SUCCESS != qe3_ret) {
		fprintf(stderr, "Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
		return;
	}

	*quote_len = quote_size;
}

void ocall_ratls_get_target_info(sgx_target_info_t* qe_target_info)
{
	int qe3_ret = sgx_qe_get_target_info(qe_target_info);
	if (SGX_QL_SUCCESS != qe3_ret) {
		fprintf(stderr, "Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
	}
}

void ocall_collect_attestation_evidence(sgx_report_t* app_report,
					ecdsa_attestation_evidence_t* evidence)
{
	ecdsa_get_quote(app_report, evidence->quote, &evidence->quote_len);
}

#elif defined(LA_REPORT)

/* Nothing */

#else   /* EPID */

/* Untrusted code to do remote attestation with the SGX SDK. */
void ocall_remote_attestation(sgx_report_t* report,
			const struct ra_tls_options* opts,
			attestation_verification_report_t* attn_report)
{
	// produce quote
	uint32_t quote_size;
	sgx_calc_quote_size(NULL, 0, &quote_size);

	sgx_quote_t *quote = (sgx_quote_t *) calloc(1, quote_size);

	sgx_status_t status;
	status = sgx_get_quote(report,
			       opts->quote_type,
			       &opts->spid,
			       NULL, NULL, 0, NULL, quote, quote_size);
	assert(SGX_SUCCESS == status);

	// verify against IAS
	obtain_attestation_verification_report(quote, quote_size, opts,
					       attn_report);
}

void ocall_sgx_init_quote(sgx_target_info_t* target_info)
{
	sgx_epid_group_id_t gid;
	sgx_status_t status = sgx_init_quote(target_info, &gid);
	assert(status == SGX_SUCCESS);
}
#endif
