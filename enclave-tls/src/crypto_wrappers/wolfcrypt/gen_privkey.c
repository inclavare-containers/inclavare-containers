#include <assert.h>
#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/crypto_wrapper.h>
#include "wolfcrypt.h"

crypto_wrapper_err_t __secured
wolfcrypt_gen_privkey(crypto_wrapper_ctx_t *ctx, enclave_tls_cert_algo_t algo,
		      uint8_t *privkey_buf, unsigned int *privkey_len)
{
	wolfcrypt_ctx_t *wc_ctx = (wolfcrypt_ctx_t *)ctx->crypto_private;
	wolfcrypt_secured_t *secured = wc_ctx->secured;

	wc_InitRsaKey(&secured->key, 0);

	RNG rng;
	wc_InitRng(&rng);
	int ret = wc_MakeRsaKey(&secured->key, 3072, 65537, &rng);
	if (ret) {
		ETLS_DEBUG("failed to generate RSA-3072 private key %d\n", ret);
		return ret;
	}

	uint8_t der[4096];
	int der_sz = wc_RsaKeyToDer(&secured->key, der, sizeof(der));
	if (der_sz < 0) {
		ETLS_DEBUG("failed to convert RSA-3072 private key to DER format %d\n", der_sz);
		return der_sz;
	}

	assert(der_sz <= sizeof(der));
	*privkey_len = der_sz;
	memcpy(privkey_buf, der, der_sz);

	return CRYPTO_WRAPPER_ERR_NONE;
}
