/* *INDENT-OFF* */
#ifndef _INTERNAL_CORE_H
#define _INTERNAL_CORE_H
/* *INDENT-ON* */

#include <enclave-tls/enclave_quote.h>
#include <enclave-tls/tls_wrapper.h>
#include <enclave-tls/api.h>

typedef struct etls_core_context_t {
	enclave_tls_conf_t config;
	unsigned long flags;
	enclave_quote_ctx_t *attester;
	enclave_quote_ctx_t *verifier;
	tls_wrapper_ctx_t *tls_wrapper;
} etls_core_context_t;

extern etls_core_context_t global_core_context;

extern enclave_tls_err_t etls_core_generate_certificate(etls_core_context_t *);

// Quote instance has been initialized
#define ENCLAVE_TLS_CTX_FLAGS_QUOTING_INITIALIZED   (1 << 0)
// TLS lib had been initialized
#define ENCLAVE_TLS_CTX_FLAGS_TLS_INITIALIZED       (1 << 16)
// TLS library has completed the creation and initialization of the TLS certificate
#define ENCLAVE_TLS_CTX_FLAGS_CERT_CREATED          (1 << 17)

/* *INDENT-OFF* */
#endif
/* *INDENT-ON* */
