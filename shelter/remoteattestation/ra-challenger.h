#ifndef _RA_CHALLENGER_H_
#define _RA_CHALLENGER_H_

#include <sgx_quote.h>

/**
 * Extract an Intel SGX quote from an Intel Attestation Service (IAS) report.
 */
void get_quote_from_report
(
    const uint8_t* report /* in */,
    const int report_len  /* in */,
    sgx_quote_t* quote
);

/**
 * Extract an Intel SGX quote from a DER-encoded X.509 certificate.
 */
void get_quote_from_cert
(
    const uint8_t* der_crt,
    uint32_t der_crt_len,
    sgx_quote_t* q
);

/**
 * Verify SGX-related X.509 extensions.
 * @return 0 if verification succeeds, 1 otherwise.
 */
int verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
);

/**
 * Pretty-print information of RA-TLS certificate to file descriptor.
 */
void dprintf_ratls_cert
(
    int fd,
    uint8_t* der_crt,
    uint32_t der_crt_len
);

#endif
