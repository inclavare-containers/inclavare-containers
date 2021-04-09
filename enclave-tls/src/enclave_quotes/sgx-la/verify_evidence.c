#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>
#include "sgx_error.h"
#include "sgx_la.h"
#include "sgx_stub_u.h"

enclave_quote_err_t sgx_la_verify_evidence(enclave_quote_ctx_t *ctx,
					   attestation_evidence_t *evidence,
					   uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	sgx_status_t retval;

	sgx_la_ctx_t *la_ctx = (sgx_la_ctx_t *) ctx->quote_private;

	sgx_status_t status = ecall_sgx_la_verify_report(la_ctx->eid, &retval,
							 (sgx_report_t *)
							 evidence->la.report);
	if (status != SGX_SUCCESS || retval != SGX_SUCCESS) {
		ETLS_ERR("sgx_la_verify_evidence() %#x\n", retval);
		return SGX_LA_ERR_CODE((int) retval);
	}

	return ENCLAVE_QUOTE_ERR_NONE;
}
