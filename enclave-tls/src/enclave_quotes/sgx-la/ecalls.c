#include <string.h>
#include <enclave-tls/enclave_quote.h>
#include "sgx_report.h"
#include "sgx_stub_t.h"
#include "sgx_utils.h"

sgx_status_t ecall_sgx_la_collect_evidence(attestation_evidence_t *evidence,
					   uint8_t *hash)
{
	sgx_status_t status;
	sgx_report_t report;
	sgx_target_info_t target_info;
	sgx_report_data_t report_data = { 0, };

	memcpy(report_data.d, hash, sizeof(hash));

	status = sgx_self_target(&target_info);
	if (status != SGX_SUCCESS)
		return status;

	status = sgx_create_report(&target_info, &report_data, &report);
	if (status != SGX_SUCCESS)
		return status;

	memcpy(evidence->la.report, &report, sizeof(report));
	evidence->la.report_len = sizeof(report);

	return SGX_SUCCESS;
}

sgx_status_t ecall_sgx_la_verify_report(sgx_report_t *report)
{
	sgx_report_t report_t;
	memcpy(&report_t, report, sizeof(sgx_report_t));
	sgx_status_t status = sgx_verify_report(&report_t);

	return status;
}
