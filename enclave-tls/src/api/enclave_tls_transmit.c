#include <enclave-tls/api.h>
#include <enclave-tls/log.h>

#include "internal/core.h"

enclave_tls_err_t enclave_tls_transmit(enclave_tls_handle handle, void *buf,
				       size_t *buf_size)
{
	ETLS_DEBUG("--- Entering enclave_tls_transmit ---\n");

	if (!handle || !(handle->tls_wrapper) || !(handle->tls_wrapper->opts) ||
	    !(handle->tls_wrapper->opts->transmit) || !buf || !buf_size)
		return -ENCLAVE_TLS_ERR_INVALID;

	enclave_tls_err_t err = -ENCLAVE_TLS_ERR_UNKNOWN;
	err = handle->tls_wrapper->opts->transmit(handle->tls_wrapper, buf,
						  buf_size);
	if (err != TLS_WRAPPER_ERR_NONE)
		return err;

	return ENCLAVE_TLS_ERR_NONE;
}
