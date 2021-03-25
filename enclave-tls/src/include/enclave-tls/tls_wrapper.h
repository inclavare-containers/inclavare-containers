/* *INDENT-OFF* */
#ifndef _ENCLAVE_TLS_WRAPPER_H
#define _ENCLAVE_TLS_WRAPPER_H
/* *INDENT-ON* */

#include <stdint.h>
#include <stddef.h>
#include <enclave-tls/compilation.h>
#include <enclave-tls/err.h>
#include <enclave-tls/api.h>
#include <enclave-tls/cert.h>

#define TLS_WRAPPER_TYPE_MAX                32
#define TLS_WRAPPER_API_VERSION_1           1
#define TLS_WRAPPER_API_VERSION_DEFAULT     TLS_WRAPPER_API_VERSION_1

#define TLS_WRAPPER_OPTS_FLAGS_SGX_ENCLAVE  1

#define TLS_TYPE_NAME_SIZE                  32
#define ENCLAVE_QUOTE_TYPE_MAX              32

typedef struct {
	void *tls_wrapper_private;
	void *userdata;
	enclave_tls_conf_t config;
} tls_wrapper_private_t;

typedef struct {
	struct tls_wrapper_opts_t *opts;
	tls_wrapper_private_t  *tls_private;
	unsigned long conf_flags;
	enclave_tls_log_level_t log_level;
	void *handle;
	int fd;
} tls_wrapper_ctx_t;

/* *INDENT-OFF* */
typedef struct tls_wrapper_opts_t {
	uint8_t version;
	unsigned long flags;
	const char type[TLS_TYPE_NAME_SIZE];
	uint8_t priority;

	tls_wrapper_err_t (*pre_init)(void);
	tls_wrapper_err_t (*init)(tls_wrapper_ctx_t *ctx);
	tls_wrapper_err_t (*use_privkey)(tls_wrapper_ctx_t *ctx,
					 void *__secured privkey_buf,
					 size_t privkey_len);
	tls_wrapper_err_t (*use_cert)(tls_wrapper_ctx_t *ctx,
				      enclave_tls_cert_info_t *cert_info);
	tls_wrapper_err_t (*negotiate)(tls_wrapper_ctx_t *ctx, int fd);
	tls_wrapper_err_t (*transmit)(tls_wrapper_ctx_t *ctx, void *buf,
				      size_t *buf_size);
	tls_wrapper_err_t (*receive)(tls_wrapper_ctx_t *ctx, void *buf,
				     size_t *buf_size);
	tls_wrapper_err_t (*cleanup)(tls_wrapper_ctx_t *ctx);
} tls_wrapper_opts_t;

extern tls_wrapper_err_t tls_wrapper_register(const tls_wrapper_opts_t *);

#endif /* _ENCLAVE_TLS_WRAPPER_H */
/* *INDENT-ON* */
