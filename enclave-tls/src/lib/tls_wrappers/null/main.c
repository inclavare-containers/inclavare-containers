#include <enclave-tls/tls_wrapper.h>
#include <enclave-tls/log.h>

extern tls_wrapper_err_t null_pre_init(void);
extern tls_wrapper_err_t null_init(tls_wrapper_ctx_t *);
extern tls_wrapper_err_t null_gen_pubkey_hash(tls_wrapper_ctx_t *,
					      enclave_tls_cert_algo_t,
					      uint8_t *);
extern tls_wrapper_err_t null_gen_cert(tls_wrapper_ctx_t *,
				       const tls_wrapper_cert_info_t *);
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
	.gen_pubkey_hash = null_gen_pubkey_hash,
	.gen_cert = null_gen_cert,
	.negotiate = null_negotiate,
	.transmit = null_transmit,
	.receive = null_receive,
	.cleanup = null_cleanup,
};

/* *INDENT-OFF* */
void __attribute__((constructor))
libtls_wrapper_null_init(void)
{
	ETLS_DEBUG("The constructor of libtls_wrapper_null.so is called\n");

	tls_wrapper_err_t err = tls_wrapper_register(&null_opts);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("ERROR: failed to register tls wrapper instance \"NULL\"\n");
	}
}
/* *INDENT-ON* */
