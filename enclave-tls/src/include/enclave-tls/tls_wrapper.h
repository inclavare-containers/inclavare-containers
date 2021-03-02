/* *INDENT-OFF* */
#ifndef _ENCLAVE_TLS_WRAPPER_H
#define _ENCLAVE_TLS_WRAPPER_H
/* *INDENT-ON* */

#include <stdint.h>
#include <stddef.h>

#include <enclave-tls/err.h>
#include <enclave-tls/api.h>

#define TLS_WRAPPER_TYPE_MAX                32
#define TLS_WRAPPER_API_VERSION_1           1
#define TLS_WRAPPER_API_VERSION_DEFAULT     TLS_WRAPPER_API_VERSION_1

#define TLS_WRAPPER_OPTS_FLAGS_SGX_ENCLAVE  1

#define TLS_TYPE_NAME_SIZE                  32
#define ENCLAVE_QUOTE_TYPE_MAX              32

typedef struct {
	struct tls_wrapper_opts_t *opts;
	void *tls_private;
	unsigned long conf_flags;
	enclave_tls_log_level_t log_level;
	void *handle;
	int fd;
} tls_wrapper_ctx_t;

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
	attestation_evidence_t evidence;
} tls_wrapper_cert_info_t;

/* *INDENT-OFF* */
typedef struct tls_wrapper_opts_t {
	uint8_t version;
	unsigned long flags;
	const char type[TLS_TYPE_NAME_SIZE];
	uint8_t priority;

	tls_wrapper_err_t(*pre_init)(void);
	tls_wrapper_err_t(*init)(tls_wrapper_ctx_t *ctx);
	tls_wrapper_err_t(*gen_pubkey_hash)(tls_wrapper_ctx_t *ctx,
					    enclave_tls_cert_algo_t algo,
					    uint8_t *hash);
	tls_wrapper_err_t(*gen_cert)(tls_wrapper_ctx_t *ctx,
				     const tls_wrapper_cert_info_t *cert_info);
	tls_wrapper_err_t(*negotiate)(tls_wrapper_ctx_t *ctx, int fd);
	tls_wrapper_err_t(*transmit)(tls_wrapper_ctx_t *ctx, void *buf,
				     size_t *buf_size);
	tls_wrapper_err_t(*receive)(tls_wrapper_ctx_t *ctx, void *buf,
				    size_t *buf_size);
	tls_wrapper_err_t(*cleanup)(tls_wrapper_ctx_t *ctx);
} tls_wrapper_opts_t;

extern tls_wrapper_err_t tls_wrapper_register(const tls_wrapper_opts_t *);

#endif /* _ENCLAVE_TLS_WRAPPER_H */
/* *INDENT-ON* */
