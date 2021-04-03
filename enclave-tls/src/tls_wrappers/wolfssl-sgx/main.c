#include <enclave-tls/tls_wrapper.h>
#include <enclave-tls/log.h>

extern tls_wrapper_err_t wolfssl_sgx_pre_init(void);
extern tls_wrapper_err_t wolfssl_sgx_init(tls_wrapper_ctx_t *);
extern tls_wrapper_err_t wolfssl_sgx_use_privkey(tls_wrapper_ctx_t *ctx,
							   void *privkey_buf,
							   size_t privkey_len);
extern tls_wrapper_err_t wolfssl_sgx_use_cert(tls_wrapper_ctx_t *ctx,
					      enclave_tls_cert_info_t *cert_info);
extern tls_wrapper_err_t wolfssl_sgx_negotiate(tls_wrapper_ctx_t *, int fd);
extern tls_wrapper_err_t wolfssl_sgx_transmit(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t wolfssl_sgx_receive(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t wolfssl_sgx_cleanup(tls_wrapper_ctx_t *);

static tls_wrapper_opts_t wolfssl_sgx_opts = {
	.api_version = TLS_WRAPPER_API_VERSION_DEFAULT,
	.type = "wolfssl_sgx",
	.priority = 50,
	.pre_init = wolfssl_sgx_pre_init,
	.init = wolfssl_sgx_init,
	.use_privkey = wolfssl_sgx_use_privkey,
	.use_cert = wolfssl_sgx_use_cert,
	.negotiate = wolfssl_sgx_negotiate,
	.transmit = wolfssl_sgx_transmit,
	.receive = wolfssl_sgx_receive,
	.cleanup = wolfssl_sgx_cleanup,
};

void __attribute__((constructor))
libtls_wrapper_wolfssl_sgx_init(void)
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err = tls_wrapper_register(&wolfssl_sgx_opts);
	if (err != TLS_WRAPPER_ERR_NONE)
		ETLS_ERR("failed to register the tls wrapper 'wolfssl_sgx' %#x\n", err);
}
