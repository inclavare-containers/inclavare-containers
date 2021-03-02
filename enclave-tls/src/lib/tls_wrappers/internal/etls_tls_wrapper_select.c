#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>

#include "internal/core.h"
#include "internal/tls_wrapper.h"

/* *INDENT-OFF* */
static enclave_tls_err_t etls_tls_wrapper_init(etls_core_context_t *ctx,
					       tls_wrapper_ctx_t *tls_ctx)
{
	if (!ctx && !tls_ctx)
		return -ENCLAVE_TLS_ERR_INIT;

	if (!ctx->tls_wrapper)
		ctx->tls_wrapper = tls_ctx;
	ctx->tls_wrapper->log_level = ctx->config.log_level;

	enclave_tls_err_t err = tls_ctx->opts->init(ctx->tls_wrapper);
	if (err != TLS_WRAPPER_ERR_NONE || !(tls_ctx->tls_private)) {
		return -ENCLAVE_TLS_ERR_INIT;
	}

	ctx->flags |= ENCLAVE_TLS_CTX_FLAGS_TLS_INITIALIZED;

	return ENCLAVE_TLS_ERR_NONE;
}

enclave_tls_err_t etls_tls_wrapper_select(etls_core_context_t *ctx,
					  const char *type)
{
	ETLS_DEBUG("etls_tls_wrapper_select() called\n");

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	unsigned int i = 0;
	for (i = 0; i < registerd_tls_wrapper_nums; ++i) {
		tls_wrapper_ctx_t *tls_ctx = tls_wrappers_ctx[i];

		if (type == NULL) {
			err = etls_tls_wrapper_init(ctx, tls_ctx);
			if (err == ENCLAVE_TLS_ERR_NONE)
				break;
		} else {
			if (strcmp(type, tls_ctx->opts->type))
				continue;
			err = etls_tls_wrapper_init(ctx, tls_ctx);
			if (err == ENCLAVE_TLS_ERR_NONE)
				break;
		}
	}

	if (i == registerd_tls_wrapper_nums) {
		ETLS_ERR("ERROR: failed to select tls wrapper\n");
		return -ENCLAVE_TLS_ERR_INIT;
	}

	return ENCLAVE_TLS_ERR_NONE;
}
/* *INDENT-ON* */
