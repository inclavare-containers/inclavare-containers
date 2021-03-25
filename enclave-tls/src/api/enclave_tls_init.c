#include <stdlib.h>
#include <string.h>
#include <enclave-tls/api.h>
#include <enclave-tls/log.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"
#include "internal/tls_wrapper.h"
#include "internal/enclave_quote.h"

/* *INDENT-OFF* */
enclave_tls_err_t enclave_tls_init(const enclave_tls_conf_t *conf,
				   enclave_tls_handle *handle)
{
	if (!conf || !handle)
		return -ENCLAVE_TLS_ERR_INVALID;

	ETLS_DEBUG("conf %p, handle %p\n", conf, handle);

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	etls_core_context_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENCLAVE_TLS_ERR_NO_MEM;

	ctx->config = *conf;
	if (ctx->config.log_level < 0 || ctx->config.log_level >= ENCLAVE_TLS_LOG_LEVEL_MAX) {
		ctx->config.log_level = global_core_context.config.log_level;
		ETLS_WARN("log level reset to global value %d\n", global_core_context.config.log_level);
	}

	if (ctx->config.cert_algo < 0 || ctx->config.cert_algo >= ENCLAVE_TLS_CERT_ALGO_MAX) {
		ctx->config.cert_algo = global_core_context.config.cert_algo;
		ETLS_WARN("certificate algorithm reset to global value %d\n",
			  global_core_context.config.cert_algo);
	}

	global_log_level = ctx->config.log_level;

	global_core_context.config.api_version = ctx->config.api_version;

	/* Select the target crypto wrapper to be used */
	char *choice = ctx->config.crypto_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.crypto_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = etls_crypto_wrapper_select(ctx, choice);
	if (err != ENCLAVE_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target enclave quote to be used */
	choice = ctx->config.attester_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.attester_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = etls_enclave_quote_select(ctx, choice, ctx->config.cert_algo);
	if (err != ENCLAVE_TLS_ERR_NONE)
		goto err_ctx;

	/* Select the target tls wrapper to be used */
	choice = ctx->config.tls_type;
	if (choice[0] == '\0') {
		choice = global_core_context.config.tls_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = etls_tls_wrapper_select(ctx, choice);
	if (err != ENCLAVE_TLS_ERR_NONE)
		goto err_ctx;

	*handle = ctx;

	ETLS_DEBUG("handle %p returned\n", ctx);

	return ENCLAVE_TLS_ERR_NONE;

err_ctx:
	free(ctx);
	return err;
}
/* *INDENT-ON* */
