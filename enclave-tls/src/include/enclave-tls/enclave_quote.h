/* *INDENT-OFF* */
#ifndef _ENCLAVE_QUOTE_H
#define _ENCLAVE_QUOTE_H
/* *INDENT-ON* */

#include <stdint.h>
#include <enclave-tls/err.h>
#include <enclave-tls/tls_wrapper.h>

typedef struct enclave_quote_ctx enclave_quote_ctx_t;

/* *INDENT-OFF* */
typedef struct {
	uint8_t version;
	unsigned long flags;
	const char type[QUOTE_TYPE_NAME_SIZE];
	uint8_t priority;

	enclave_quote_err_t(*pre_init)(void);
	enclave_quote_err_t(*init)(enclave_quote_ctx_t *ctx,
				   enclave_tls_cert_algo_t algo);
	enclave_quote_err_t(*collect_evidence)(enclave_quote_ctx_t *ctx,
					       attestation_evidence_t *evidence,
					       enclave_tls_cert_algo_t algo,
					       uint8_t *hash);
	enclave_quote_err_t(*verify_evidence)(enclave_quote_ctx_t *ctx,
					      attestation_evidence_t *evidence,
					      uint8_t *hash);
	enclave_quote_err_t(*collect_collateral)(enclave_quote_ctx_t *ctx);
	enclave_quote_err_t(*cleanup)(enclave_quote_ctx_t *ctx);
} enclave_quote_opts_t;
/* *INDENT-ON* */

struct enclave_quote_ctx {
	enclave_quote_opts_t *opts;
	void *quote_private;
	enclave_tls_log_level_t log_level;
	void *handle;
	union {
		struct {
			const char name[QUOTE_TYPE_NAME_SIZE];
			uint8_t spid[ENCLAVE_SGX_SPID_LENGTH];
			bool linkable;
		} sgx_epid;

		struct {
			const char name[QUOTE_TYPE_NAME_SIZE];
			uint8_t cert_type;
			quote_sgx_ecdsa_verification_type_t verification_type;
		} sgx_ecdsa;
	} config;
};

#define ENCLAVE_QUOTE_API_VERSION_1             1
#define ENCLAVE_QUOTE_API_VERSION_DEFAULT       ENCLAVE_QUOTE_API_VERSION_1
#define ENCLAVE_QUOTE_OPTS_FLAGS_SGX_ENCLAVE    1
#define ENCLAVE_QUOTE_FLAGS_DEFAULT             0
/* *INDENT-OFF* */
#endif /* _ENCLAVE_QUOTE_H */
/* *INDENT-ON* */
