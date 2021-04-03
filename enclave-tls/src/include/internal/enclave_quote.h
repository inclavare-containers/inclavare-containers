#ifndef _INTERNAL_ENCLAVE_QUOTE_H
#define _INTERNAL_ENCLAVE_QUOTE_H

#include <enclave-tls/enclave_quote.h>
#include "internal/core.h"

#define ENCLAVE_QUOTES_DIR    "/opt/enclave-tls/lib/enclave-quotes/"

extern enclave_tls_err_t etls_enclave_quote_load_all(void);
extern enclave_tls_err_t etls_enclave_quote_load_single(const char *);
extern enclave_tls_err_t etls_enclave_quote_select(etls_core_context_t *,
						   const char *,
						   enclave_tls_cert_algo_t);

extern enclave_quote_opts_t *enclave_quotes_opts[ENCLAVE_QUOTE_TYPE_MAX];
extern enclave_quote_ctx_t *enclave_quotes_ctx[ENCLAVE_QUOTE_TYPE_MAX];
extern unsigned int enclave_quote_nums;
extern unsigned int registerd_enclave_quote_nums;

#endif
