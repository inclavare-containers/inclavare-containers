#include <assert.h>
#include <string.h>

#include <sgx_uae_service.h>

#include "ra.h"
#include "ra-attester.h"
#include "ra_private.h"
#include "ra_tls_t.h" // OCALLs

/* Trusted portion (called from within the enclave) to do remote
   attestation with the SGX SDK.  */
void do_remote_attestation
(
    sgx_report_data_t* report_data,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
)
{
    sgx_target_info_t target_info = {0, };
    ocall_sgx_init_quote(&target_info);

    sgx_report_t report = {0, };
    sgx_status_t status = sgx_create_report(&target_info, report_data, &report);
    assert(status == SGX_SUCCESS);

    ocall_remote_attestation(&report, opts, attn_report);
}

void ra_tls_create_report(
    sgx_report_t* report
)
{
    sgx_target_info_t target_info = {0, };
    sgx_report_data_t report_data = {0, };
    memset(report, 0, sizeof(*report));

    sgx_create_report(&target_info, &report_data, report);
}
