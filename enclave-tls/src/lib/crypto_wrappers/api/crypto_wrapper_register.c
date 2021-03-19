#include <stdlib.h>
#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/crypto_wrapper.h"

/* *INDENT-OFF* */
crypto_wrapper_err_t crypto_wrapper_register(const crypto_wrapper_opts_t *opts)
{
	if (!opts)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	ETLS_DEBUG("called with crypto wrapper '%s'\n", opts->type);

	crypto_wrapper_opts_t *new_opts =
		(crypto_wrapper_opts_t *) malloc(sizeof(*new_opts));
	if (!new_opts)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	memcpy(new_opts, opts, sizeof(*new_opts));

	if ((new_opts->type[0] == '\0') ||
	    (new_opts->version < CRYPTO_WRAPPER_API_VERSION_DEFAULT)) {
		free(new_opts);
		return -CRYPTO_WRAPPER_ERR_INVALID;
	}

	crypto_wrappers_opts[registerd_crypto_wrapper_nums++] = new_opts;

	ETLS_INFO("the crypto wrapper '%s' registered\n", opts->type);

	return CRYPTO_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
