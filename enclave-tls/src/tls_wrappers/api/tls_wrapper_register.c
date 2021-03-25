#include <stdlib.h>
#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>

#include "internal/tls_wrapper.h"

/* *INDENT-OFF* */
tls_wrapper_err_t tls_wrapper_register(const tls_wrapper_opts_t *opts)
{
	ETLS_DEBUG("called with tls wrapper '%s'\n", opts->type);

	tls_wrapper_opts_t *new_opts = (tls_wrapper_opts_t *) malloc(sizeof(*new_opts));
	if (!new_opts)
		return -TLS_WRAPPER_ERR_NO_MEM;

	memcpy(new_opts, opts, sizeof(*new_opts));
	if ((new_opts->version < TLS_WRAPPER_API_VERSION_DEFAULT) ||
	    (new_opts->priority < 0) || (new_opts->flags < 0)) {
		free(new_opts);
		return -TLS_WRAPPER_ERR_INVALID;
	}

	tls_wrappers_opts[registerd_tls_wrapper_nums++] = new_opts;

	return TLS_WRAPPER_ERR_NONE;
}
/* *INDENT-ON* */
