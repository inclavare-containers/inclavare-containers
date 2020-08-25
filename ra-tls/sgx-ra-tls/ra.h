#ifndef _RA_H_
#define _RA_H_

typedef struct {
    uint8_t ias_report[2*1024];
    uint32_t ias_report_len;
    uint8_t ias_sign_ca_cert[2*1024];
    uint32_t ias_sign_ca_cert_len;
    uint8_t ias_sign_cert[2*1024];
    uint32_t ias_sign_cert_len;
    uint8_t ias_report_signature[2*1024];
    uint32_t ias_report_signature_len;
} attestation_verification_report_t;

static const int rsa_3072_der_len = 1766;
static const int rsa_pub_3072_pcks_der_len = 422;
static const int rsa_pub_3072_pcks_header_len = 24;
static const int rsa_pub_3072_raw_der_len = 398; /* rsa_pub_3072_pcks_der_len - pcks_nr_1_header_len */

typedef struct {
    uint8_t quote[2048];
    uint32_t quote_len;
    /* Certificiate in PEM format. */
    uint8_t pck_crt[2048];
    uint32_t pck_crt_len;
    /* Certificate chain in PEM format. */
    uint8_t pck_sign_chain[4096];
    uint32_t pck_sign_chain_len;
    /* JSON data as published by
       https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info */
    uint8_t tcb_info[4096];
    uint32_t tcb_info_len;
    /* Certificate chain in PEM format. */
    uint8_t tcb_sign_chain[4096];
    uint32_t tcb_sign_chain_len;
    /* JSON data, e.g., as obtained from
       https://api.portal.trustedservices.intel.com/documentation#pcs-qe-identity */
    uint8_t qe_identity[1024];
    uint32_t qe_identity_len;
    /* PEM-encoded CRL as published by
       https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl */
    uint8_t root_ca_crl[1024];
    uint32_t root_ca_crl_len;
    /* PEM-encoded certificate revocation list as published by
       https://api.portal.trustedservices.intel.com/documentation#pcs-revocation */
    uint8_t pck_crl[1024];
    uint32_t pck_crl_len;
    
} ecdsa_attestation_evidence_t;

#endif
