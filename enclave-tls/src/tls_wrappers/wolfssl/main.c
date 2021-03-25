#include <enclave-tls/tls_wrapper.h>
#include <enclave-tls/log.h>
#include <enclave-tls/cert.h>

extern tls_wrapper_err_t wolfssl_pre_init(void);
extern tls_wrapper_err_t wolfssl_init(tls_wrapper_ctx_t *);
extern tls_wrapper_err_t __secured wolfssl_use_privkey(tls_wrapper_ctx_t *ctx,
						       void *__secured privkey_buf,
						       size_t privkey_len);
extern tls_wrapper_err_t wolfssl_use_cert(tls_wrapper_ctx_t *ctx,
					  enclave_tls_cert_info_t *cert_info);
extern tls_wrapper_err_t wolfssl_negotiate(tls_wrapper_ctx_t *, int fd);
extern tls_wrapper_err_t wolfssl_transmit(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t wolfssl_receive(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t wolfssl_cleanup(tls_wrapper_ctx_t *);

static tls_wrapper_opts_t wolfssl_opts = {
	.version = TLS_WRAPPER_API_VERSION_DEFAULT,
	.type = "wolfssl",
	.priority = 20,
	.pre_init = wolfssl_pre_init,
	.init = wolfssl_init,
	.use_privkey = wolfssl_use_privkey,
	.use_cert = wolfssl_use_cert,
	.negotiate = wolfssl_negotiate,
	.transmit = wolfssl_transmit,
	.receive = wolfssl_receive,
	.cleanup = wolfssl_cleanup,
};

/* *INDENT-OFF* */
void __attribute__((constructor))
libtls_wrapper_wolfssl_init(void)
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err = tls_wrapper_register(&wolfssl_opts);
	if (err != TLS_WRAPPER_ERR_NONE)
		ETLS_FATAL("failed to register the tls wrapper instance 'wolfssl'\n");
}
/* *INDENT-ON* */
