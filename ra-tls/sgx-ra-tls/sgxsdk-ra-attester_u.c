#include <assert.h>
#include <stdlib.h>

#include <sgx_uae_service.h>

#include <ra.h>
#include <ra-attester.h>
#include <ias-ra.h>

/* Untrusted code to do remote attestation with the SGX SDK. */

void ocall_remote_attestation
(
    sgx_report_t* report,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
)
{
    // produce quote
    uint32_t quote_size;
    sgx_calc_quote_size(NULL, 0, &quote_size);
    
    sgx_quote_t* quote = (sgx_quote_t*) calloc(1, quote_size);
    
    sgx_status_t status;
    status = sgx_get_quote(report,
                           opts->quote_type,
                           &opts->spid,
                           NULL,
                           NULL,
                           0,
                           NULL,
                           quote,
                           quote_size);
    assert(SGX_SUCCESS == status);

    // verify against IAS
    obtain_attestation_verification_report(quote, quote_size, opts, attn_report);
}

void ocall_sgx_init_quote
(
    sgx_target_info_t* target_info
)
{
    sgx_epid_group_id_t gid;
    sgx_status_t status = sgx_init_quote(target_info, &gid);
    assert(status == SGX_SUCCESS);
}
