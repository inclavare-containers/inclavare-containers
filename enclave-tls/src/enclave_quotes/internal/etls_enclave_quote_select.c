#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>

#include "internal/enclave_quote.h"
#include "internal/core.h"

/* *INDENT-OFF* */
static enclave_tls_err_t etls_enclave_quote_init(etls_core_context_t *ctx,
						 enclave_quote_ctx_t *quote_ctx,
						 enclave_tls_cert_algo_t algo)
{
	if (!ctx || !quote_ctx) {
		return -ENCLAVE_TLS_ERR_INIT;
	}

	/* Enclave Quote instance must set quote private in init() */
	enclave_tls_err_t err = quote_ctx->opts->init(quote_ctx, algo);
	if (err != ENCLAVE_QUOTE_ERR_NONE || !(quote_ctx->quote_private)) {
		return -ENCLAVE_TLS_ERR_INIT;
	}

	/* The first quote_ctx has a higher priority than the other quote_ctx */
	if (!ctx->attester)
		ctx->attester = quote_ctx;

	if (!ctx->verifier)
		ctx->verifier = quote_ctx;

	ctx->flags |= ENCLAVE_TLS_CTX_FLAGS_QUOTING_INITIALIZED;

	return ENCLAVE_TLS_ERR_NONE;
}

enclave_tls_err_t etls_enclave_quote_select(etls_core_context_t *ctx,
					    const char *type,
					    enclave_tls_cert_algo_t algo)
{
	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	enclave_quote_ctx_t *quote_ctx = NULL;
	unsigned int i = 0;
	unsigned int err_num = 0;
	for (i = 0; i < registerd_enclave_quote_nums; ++i) {
		quote_ctx = enclave_quotes_ctx[i];
		quote_ctx->eid = ctx->config.eid;

		if (type == NULL) {
			err = etls_enclave_quote_init(ctx, quote_ctx, algo);
			if (err != ENCLAVE_TLS_ERR_NONE)
				err_num++;
		} else {
			if (strcmp(type, quote_ctx->opts->type))
				continue;

			err = etls_enclave_quote_init(ctx, quote_ctx, algo);
			if (err != ENCLAVE_TLS_ERR_NONE) {
				ETLS_ERR("ERROR: failed to init enclave quote %s\n", type);
				return -ENCLAVE_TLS_ERR_INIT;
			}
			break;
		}
	}

	if (err_num == registerd_enclave_quote_nums) {
		ETLS_ERR("failed to initialize all enclave quotes\n");
		return -ENCLAVE_TLS_ERR_INIT;
	}

	if ((i == registerd_enclave_quote_nums) && (type != NULL)) {
		ETLS_ERR("invalid enclave quote type %s\n", type);
		return -ENCLAVE_TLS_ERR_INVALID;
	}

	ETLS_INFO("the enclave quote '%s' selected\n", ctx->attester->opts->type);

	return ENCLAVE_TLS_ERR_NONE;
}
/* *INDENT-ON* */
