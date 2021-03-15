#include <enclave-tls/tls_wrapper.h>
#include <enclave-tls/log.h>

extern tls_wrapper_err_t wolfssl_pre_init(void);
extern tls_wrapper_err_t wolfssl_init(tls_wrapper_ctx_t *);
extern tls_wrapper_err_t wolfssl_gen_pubkey_hash(tls_wrapper_ctx_t *,
						 enclave_tls_cert_algo_t,
						 uint8_t *);
extern tls_wrapper_err_t wolfssl_gen_cert(tls_wrapper_ctx_t *,
					  const tls_wrapper_cert_info_t *);
extern tls_wrapper_err_t wolfssl_negotiate(tls_wrapper_ctx_t *, int fd);
extern tls_wrapper_err_t wolfssl_transmit(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t wolfssl_receive(tls_wrapper_ctx_t *, void *, size_t *);
extern tls_wrapper_err_t wolfssl_cleanup(tls_wrapper_ctx_t *);

static tls_wrapper_opts_t wolfssl_opts = {
	.version = TLS_WRAPPER_API_VERSION_DEFAULT,
	.type = "wolfssl",
	.priority = 1,
	.pre_init = wolfssl_pre_init,
	.init = wolfssl_init,
	.gen_pubkey_hash = wolfssl_gen_pubkey_hash,
	.gen_cert = wolfssl_gen_cert,
	.negotiate = wolfssl_negotiate,
	.transmit = wolfssl_transmit,
	.receive = wolfssl_receive,
	.cleanup = wolfssl_cleanup,
};

/* *INDENT-OFF* */
void __attribute__((constructor))
libtls_wrapper_wolfssl_init(void)
{
	ETLS_DEBUG("The constructor of libtls_wrapper_wolfssl.so is called\n");

	tls_wrapper_err_t err = tls_wrapper_register(&wolfssl_opts);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("ERROR: failed to register tls wrapper instance \"WOLFSSL\"\n");
	}
}
/* *INDENT-ON* */
