/* Interface to do remote attestation against Intel Attestation
   Service. Two implementations exist: (1) sgxsdk-ra-attester_* to be
   used with the SGX SDK. (2) nonsdk-ra-attester.c to be used with
   Graphene-SGX. */

#ifndef _RA_PRIVATE_H
#define _RA_PRIVATE_H

struct ra_tls_options;

void do_remote_attestation(sgx_report_data_t* report_data,
                           const struct ra_tls_options* opts,
                           attestation_verification_report_t* r);

extern const uint8_t ias_response_body_oid[];
extern const uint8_t ias_root_cert_oid[];
extern const uint8_t ias_leaf_cert_oid[];
extern const uint8_t ias_report_signature_oid[];

extern const uint8_t quote_oid[];
extern const uint8_t pck_crt_oid[];
extern const uint8_t pck_sign_chain_oid[];
extern const uint8_t tcb_info_oid[];
extern const uint8_t tcb_sign_chain_oid[];
extern const uint8_t qe_identity_oid[];
extern const uint8_t root_ca_crl_oid[];
extern const uint8_t pck_crl_oid[];

extern const size_t ias_oid_len;

#endif
