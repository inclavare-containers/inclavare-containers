#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/log.h>
#include <enclave-tls/cert.h>

extern crypto_wrapper_err_t wolfcrypt_pre_init(void);
extern crypto_wrapper_err_t wolfcrypt_init(crypto_wrapper_ctx_t *);
extern crypto_wrapper_err_t __secured wolfcrypt_gen_privkey(crypto_wrapper_ctx_t *ctx,
							    enclave_tls_cert_algo_t algo,
						  	    uint8_t *privkey_buf,
							    unsigned int *privkey_len);
extern crypto_wrapper_err_t wolfcrypt_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
						      enclave_tls_cert_algo_t algo,
						      uint8_t *hash);
extern crypto_wrapper_err_t wolfcrypt_gen_cert(crypto_wrapper_ctx_t *ctx,
					       enclave_tls_cert_info_t *cert_info);
extern crypto_wrapper_err_t wolfcrypt_cleanup(crypto_wrapper_ctx_t *);

static crypto_wrapper_opts_t wolfcrypt_opts = {
	.version = CRYPTO_WRAPPER_API_VERSION_DEFAULT,
	.type = "wolfcrypt",
	.priority = 10,
	.pre_init = wolfcrypt_pre_init,
	.init = wolfcrypt_init,
	.gen_privkey = wolfcrypt_gen_privkey,
	.gen_pubkey_hash = wolfcrypt_gen_pubkey_hash,
	.gen_cert = wolfcrypt_gen_cert,
	.cleanup = wolfcrypt_cleanup,
};

/* *INDENT-OFF* */
void __attribute__((constructor))
libcrypto_wrapper_wolfcrypt_init(void)
{
	ETLS_DEBUG("called\n");

	crypto_wrapper_err_t err = crypto_wrapper_register(&wolfcrypt_opts);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		ETLS_FATAL("failed to register crypto wrapper instance wolfcrypt %#x\n", err);
}
/* *INDENT-ON* */
