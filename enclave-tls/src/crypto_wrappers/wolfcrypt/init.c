#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "wolfcrypt.h"

/* *INDENT-OFF* */
static void *__secured wolfcrypt_init_secured(void)
{
	wolfcrypt_secured_t *secured = calloc(1, sizeof(*secured));

	if (!secured)
		return NULL;

	return secured;	
}

crypto_wrapper_err_t wolfcrypt_init(crypto_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("ctx %p\n", ctx);

	wolfcrypt_ctx_t *wc_ctx = calloc(1, sizeof(*wc_ctx));
	if (!wc_ctx)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	wc_ctx->secured = wolfcrypt_init_secured();
	if (!wc_ctx->secured) {
		free(wc_ctx);
		return -CRYPTO_WRAPPER_ERR_NO_MEM;
	}

	ctx->crypto_private = wc_ctx;

	return CRYPTO_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
