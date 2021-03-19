/* *INDENT-OFF* */
#ifndef _ENCLAVE_CRYPTO_WRAPPER_H
#define _ENCLAVE_CRYPTO_WRAPPER_H
/* *INDENT-ON* */

#include <stdint.h>
#include <stddef.h>
#include <enclave-tls/compilation.h>
#include <enclave-tls/err.h>
#include <enclave-tls/api.h>
#include <enclave-tls/cert.h>

#define CRYPTO_WRAPPER_TYPE_MAX                32
#define CRYPTO_WRAPPER_API_VERSION_1           1
#define CRYPTO_WRAPPER_API_VERSION_DEFAULT     CRYPTO_WRAPPER_API_VERSION_1

#define CRYPTO_WRAPPER_OPTS_FLAGS_SGX_ENCLAVE  1

#define CRYPTO_TYPE_NAME_SIZE                  32
#define ENCLAVE_QUOTE_TYPE_MAX                 32

typedef struct {
	struct crypto_wrapper_opts_t *opts;
	void *crypto_private;
	unsigned long conf_flags;
	enclave_tls_log_level_t log_level;
	enclave_tls_cert_algo_t cert_algo;
	void *handle;
} crypto_wrapper_ctx_t;

/* *INDENT-OFF* */
typedef struct crypto_wrapper_opts_t {
	uint8_t version;
	unsigned long flags;
	const char type[CRYPTO_TYPE_NAME_SIZE];
	uint8_t priority;

	crypto_wrapper_err_t (*pre_init)(void);
	crypto_wrapper_err_t (*init)(crypto_wrapper_ctx_t *ctx);
	crypto_wrapper_err_t (*gen_privkey)(crypto_wrapper_ctx_t *ctx,
					    enclave_tls_cert_algo_t algo,
					    uint8_t *privkey_buf,
					    unsigned int *privkey_len);
	crypto_wrapper_err_t (*gen_pubkey_hash)(crypto_wrapper_ctx_t *ctx,
						enclave_tls_cert_algo_t algo,
						uint8_t *hash);
	crypto_wrapper_err_t (*gen_cert)(crypto_wrapper_ctx_t *ctx,
					 enclave_tls_cert_info_t *cert_info);
	crypto_wrapper_err_t (*cleanup)(crypto_wrapper_ctx_t *ctx);
} crypto_wrapper_opts_t;

extern crypto_wrapper_err_t crypto_wrapper_register(const crypto_wrapper_opts_t *);

#endif /* _ENCLAVE_CRYPTO_WRAPPER_H */
/* *INDENT-ON* */
