#include <sgx_dcap_quoteverify.h>
#include <sgx_dcap_ql_wrapper.h>
#include <enclave-tls/log.h>
#include "sgx_stub_u.h"

/* *INDENT-OFF* */
void ocall_ratls_get_target_info(sgx_target_info_t *qe_target_info)
{
	int qe3_ret = sgx_qe_get_target_info(qe_target_info);
	if (SGX_QL_SUCCESS != qe3_ret)
		ETLS_ERR("sgx_qe_get_target_info() with error code 0x%04x\n", qe3_ret);
}
/* *INDENT-ON* */
