#ifndef __RA_ATTESTER_PRIVATE_H__
#define __RA_ATTESTER_PRIVATE_H__

void create_report
(
    sgx_target_info_t* target_info,
    const sgx_report_data_t* report_data,
    sgx_report_t* report
);

#endif
