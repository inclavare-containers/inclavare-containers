#include <enclave-tls/tls_wrapper.h>
#include <enclave-tls/log.h>
#include <enclave-tls/cert.h>

extern tls_wrapper_err_t null_pre_init(void);
extern tls_wrapper_err_t null_init(tls_wrapper_ctx_t *);
extern tls_wrapper_err_t null_use_privkey(tls_wrapper_ctx_t *ctx,
					  void *__secured privkey_buf,
					  size_t privkey_len);
extern tls_wrapper_err_t null_use_cert(tls_wrapper_ctx_t *ctx,
				       enclave_tls_cert_info_t *cert_info);
extern tls_wrapper_err_t null_negotiate(tls_wrapper_ctx_t *, int fd);
extern tls_wrapper_err_t null_transmit(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t null_receive(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t null_cleanup(tls_wrapper_ctx_t *);

static tls_wrapper_opts_t null_opts = {
	.version = TLS_WRAPPER_API_VERSION_DEFAULT,
	.type = "null",
	.priority = 0,
	.pre_init = null_pre_init,
	.init = null_init,
	.use_privkey = null_use_privkey,
	.use_cert = null_use_cert,
	.negotiate = null_negotiate,
	.transmit = null_transmit,
	.receive = null_receive,
	.cleanup = null_cleanup,
};

/* *INDENT-OFF* */
void __attribute__((constructor))
libtls_wrapper_null_init(void)
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err = tls_wrapper_register(&null_opts);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("ERROR: failed to register tls wrapper instance \"NULL\"\n");
	}
}
/* *INDENT-ON* */
