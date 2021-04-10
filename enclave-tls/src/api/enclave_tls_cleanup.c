#include <stdlib.h>
#include <dlfcn.h>
#include <enclave-tls/api.h>
#include <enclave-tls/log.h>

#include "internal/core.h"
#include "internal/enclave_quote.h"
#include "internal/tls_wrapper.h"

enclave_tls_err_t enclave_tls_cleanup(enclave_tls_handle handle)
{
	ETLS_DEBUG("--- Entering enclave_tls_cleanup ---\n");

	if (!handle || !(handle->tls_wrapper) || !(handle->tls_wrapper->opts) ||
	    !(handle->tls_wrapper->opts->cleanup) || !(handle->attester) ||
	    !(handle->attester->opts) || !(handle->attester->opts->cleanup) ||
	    !(handle->verifier) || !(handle->verifier->opts) ||
	    !(handle->verifier->opts->cleanup))
		return -ENCLAVE_TLS_ERR_INVALID;

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;

	err = handle->tls_wrapper->opts->cleanup(handle->tls_wrapper);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("ERROR: tls_wrapper_cleanup()\n");
		return err;
	}

	if (handle->attester != handle->verifier) {
		err = handle->attester->opts->cleanup(handle->attester);
		if (err != ENCLAVE_QUOTE_ERR_NONE) {
			ETLS_ERR("ERROR: attester_quote_cleanup()\n");
			return err;
		}
	}

	err = handle->verifier->opts->cleanup(handle->verifier);
	if (err != ENCLAVE_QUOTE_ERR_NONE) {
		ETLS_ERR("ERROR: attester_quote_cleanup()\n");
		return err;
	}

	for (unsigned int i = 0; i < tls_wrappers_nums; ++i) {
		if (tls_wrappers_ctx[i] != NULL) {
			if (tls_wrappers_ctx[i]->handle != NULL)
				dlclose(tls_wrappers_ctx[i]->handle);
			free(tls_wrappers_ctx[i]);
		}
	}

	for (unsigned int i = 0; i < enclave_quote_nums; ++i) {
		if (enclave_quotes_ctx[i] != NULL) {
			if (enclave_quotes_ctx[i]->handle != NULL)
				dlclose(enclave_quotes_ctx[i]->handle);
			free(enclave_quotes_ctx[i]);
		}
	}

	free(handle);

	return ENCLAVE_TLS_ERR_NONE;
}
