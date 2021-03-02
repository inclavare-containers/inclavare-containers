#include <stdlib.h>
#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>

#include "internal/enclave_quote.h"

/* *INDENT-OFF* */
enclave_quote_err_t enclave_quote_register(const enclave_quote_opts_t *opts)
{
	ETLS_DEBUG("enclave_quote_register() called with quote type: '%s'\n",
		   opts->type);

	enclave_quote_opts_t *new_opts =
		(enclave_quote_opts_t *) malloc(sizeof(*new_opts));
	if (!new_opts)
		return -ENCLAVE_QUOTE_ERR_NO_MEM;

	memcpy(new_opts, opts, sizeof(*new_opts));
	if ((new_opts->version < ENCLAVE_QUOTE_API_VERSION_DEFAULT) ||
	    (new_opts->priority < 0) || (new_opts->flags < 0)) {
		free(new_opts);
		return -ENCLAVE_QUOTE_ERR_INVALID;
	}

	enclave_quotes_opts[registerd_enclave_quote_nums++] = new_opts;

	return ENCLAVE_QUOTE_ERR_NONE;
}
/* *INDENT-ON* */
