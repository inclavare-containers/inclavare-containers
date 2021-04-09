#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>
#include <string.h>
#include <sgx_report.h>
#include "sgx_stub_u.h"
#include "sgx_la.h"

enclave_quote_err_t sgx_la_collect_evidence(enclave_quote_ctx_t *ctx,
					    attestation_evidence_t *evidence,
					    enclave_tls_cert_algo_t algo,
					    uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence,
		   algo, hash);

	sgx_la_ctx_t *la_ctx = (sgx_la_ctx_t *) ctx->quote_private;

	sgx_status_t retval;

	sgx_status_t status =
		ecall_sgx_la_collect_evidence(la_ctx->eid, &retval, evidence,
					      hash);
	if (status != SGX_SUCCESS || retval != SGX_SUCCESS) {
		ETLS_ERR("sgx_la_collect_evidence() %#x\n", retval);
		return SGX_LA_ERR_CODE((int) retval);
	}

	strcpy(evidence->type, "sgx_la");

	return ENCLAVE_QUOTE_ERR_NONE;
}
