#include <stdint.h>
#include <stddef.h>

#include <sgx_quote.h>

extern const uint8_t ias_response_body_oid[];
extern const uint8_t ias_root_cert_oid[];
extern const uint8_t ias_leaf_cert_oid[];
extern const uint8_t ias_report_signature_oid[];

extern const uint8_t quote_oid[];
extern const uint8_t pck_crt_oid[];
extern const uint8_t pck_sign_chain_oid[];
extern const uint8_t tcb_info_oid[];
extern const uint8_t tcb_sign_chain_oid[];

extern const size_t ias_oid_len;

void get_quote_from_extension
(
    const uint8_t* ext,
    size_t ext_len,
    sgx_quote_t* q
);

int find_oid
(
     const unsigned char* ext, size_t ext_len,
     const unsigned char* oid, size_t oid_len,
     unsigned char** val, size_t* len
);

void extract_x509_extensions
(
    const uint8_t* ext,
    int ext_len,
    attestation_verification_report_t* attn_report
);

int extract_x509_extension
(
    const uint8_t* ext,
    int ext_len,
    const uint8_t* oid,
    size_t oid_len,
    uint8_t* data,
    uint32_t* data_len,
    uint32_t data_max_len
);

void ecdsa_extract_x509_extensions
(
    uint8_t* ext,
    int ext_len,
    ecdsa_attestation_evidence_t* evidence
);

/**
 * @return 1 if it is an EPID-based attestation RA-TLS
 * certificate. Otherwise, 0.
 */
int is_epid_ratls_cert
(
    const uint8_t* der_crt,
    uint32_t der_crt_len
);
