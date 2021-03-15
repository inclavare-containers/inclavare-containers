#include <stdlib.h>
#include <string.h>
#include <enclave-tls/api.h>
#include <enclave-tls/log.h>

#include "internal/core.h"
#include "internal/tls_wrapper.h"
#include "internal/enclave_quote.h"

/* *INDENT-OFF* */
enclave_tls_err_t enclave_tls_init(const enclave_tls_conf_t *conf,
				   enclave_tls_handle *handle)
{
	ETLS_DEBUG("------ Entering running process ------ \n");
	ETLS_DEBUG("--- Entering enclave_tls_init ---\n");

	if (!handle || !conf)
		return -ENCLAVE_TLS_ERR_INVALID;

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	etls_core_context_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		err = -ENCLAVE_TLS_ERR_NO_MEM;
		return err;
	}

	ctx->config = *conf;
	if (ctx->config.api_version < 0 || ctx->config.log_level < 0 ||
	    ctx->config.flags < 0) {
		err = -ENCLAVE_TLS_ERR_INVALID;
		goto err_ctx;
	}

	enclave_tls_cert_algo_t algo = global_core_context.config.cert_algo;
	if (conf->cert_algo > 0)
		algo = conf->cert_algo;

	global_log_level = conf->log_level;

	if (conf->api_version > 0)
		global_core_context.config.api_version = conf->api_version;

	/* Select the final Enclave quote type to be used */
	if (strlen(ctx->config.attester_type) > 0)
		err = etls_enclave_quote_select(ctx, ctx->config.attester_type,
						algo);
	else if (strlen(global_core_context.config.attester_type) > 0)
		err = etls_enclave_quote_select(ctx,
						global_core_context.config.
						attester_type, algo);
	else
		err = etls_enclave_quote_select(ctx, NULL, algo);
	if (err != ENCLAVE_TLS_ERR_NONE) {
		ETLS_ERR("ERROR: failed to etls_enclave_quote_select()\n");
		goto err_ctx;
	}

	/* Select the final TLS Wrapper instance type to be used */
	if (strlen(ctx->config.tls_type) > 0)
		err = etls_tls_wrapper_select(ctx, ctx->config.tls_type);
	else if (strlen(global_core_context.config.tls_type) > 0)
		err = etls_tls_wrapper_select(ctx,
					      global_core_context.config.
					      tls_type);
	else
		err = etls_tls_wrapper_select(ctx, NULL);
	if (err != ENCLAVE_TLS_ERR_NONE) {
		ETLS_ERR("ERROR: failed to etls_tls_wrapper_select()\n");
		goto err_ctx;
	}

	*handle = ctx;

	return ENCLAVE_TLS_ERR_NONE;

err_ctx:
	free(ctx);
	return err;
}
/* *INDENT-ON* */
