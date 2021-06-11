#include "enclave-tls/api.h"

enclave_tls_err_t ecall_enclave_tls_init(const enclave_tls_conf_t *conf,
                                         enclave_tls_handle handle)
{
	libenclave_tls_init();

	return enclave_tls_init(conf, &handle);
}

enclave_tls_err_t ecall_enclave_tls_negotiate(enclave_tls_handle handle, int fd)
{
	return enclave_tls_negotiate(handle, fd);
}

enclave_tls_err_t ecall_enclave_tls_transmit(enclave_tls_handle handle,
                                             void *buf,
                                             size_t *buf_size)
{
	return enclave_tls_transmit(handle, buf, buf_size);
}

enclave_tls_err_t ecall_enclave_tls_receive(enclave_tls_handle handle,
                                            void *buf,
                                            size_t *buf_size)
{
	return enclave_tls_receive(handle, buf, buf_size);
}

enclave_tls_err_t ecall_enclave_tls_cleanup(enclave_tls_handle handle)
{
	return enclave_tls_cleanup(handle);
}
