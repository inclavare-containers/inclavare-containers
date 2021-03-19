/* *INDENT-OFF* */
#ifndef _ENCLAVE_CERT_H
#define _ENCLAVE_CERT_H
/* *INDENT-ON* */

typedef struct {
	const char *organization;
	const char *organization_unit;
	const char *common_name;
} cert_subject_t;

typedef struct {
	uint8_t ias_report[2 * 1024];
	uint32_t ias_report_len;
	uint8_t ias_sign_ca_cert[2 * 1024];
	uint32_t ias_sign_ca_cert_len;
	uint8_t ias_sign_cert[2 * 1024];
	uint32_t ias_sign_cert_len;
	uint8_t ias_report_signature[2 * 1024];
	uint32_t ias_report_signature_len;
} attestation_verification_report_t;

typedef struct {
	uint8_t quote[2048];
	uint32_t quote_len;
	/* Certificiate in PEM format. */
	uint8_t pck_crt[2048];
	uint32_t pck_crt_len;
	/* Certificate chain in PEM format. */
	uint8_t pck_sign_chain[4096];
	uint32_t pck_sign_chain_len;
	/* JSON data as published by https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info */
	uint8_t tcb_info[4096];
	uint32_t tcb_info_len;
	/* Certificate chain in PEM format. */
	uint8_t tcb_sign_chain[4096];
	uint32_t tcb_sign_chain_len;
	/* JSON data, e.g., as obtained from https://api.portal.trustedservices.intel.com/documentation#pcs-qe-identity */
	uint8_t qe_identity[1024];
	uint32_t qe_identity_len;
	/* PEM-encoded CRL as published by https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl */
	uint8_t root_ca_crl[1024];
	uint32_t root_ca_crl_len;
	/* PEM-encoded certificate revocation list as published by https://api.portal.trustedservices.intel.com/documentation#pcs-revocation */
	uint8_t pck_crl[1024];
	uint32_t pck_crl_len;
} ecdsa_attestation_evidence_t;

typedef struct {
	const char type[QUOTE_TYPE_NAME_SIZE];
	union {
		attestation_verification_report_t epid;
		ecdsa_attestation_evidence_t ecdsa;
	};
} attestation_evidence_t;

typedef struct {
	cert_subject_t subject;
	unsigned int cert_len;
	uint8_t cert_buf[8192];
	attestation_evidence_t evidence;
} enclave_tls_cert_info_t;

/* *INDENT-OFF* */
#endif
/* *INDENT-ON* */
