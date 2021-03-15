#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>

#include "wolfssl_private.h"

const int rsa_pub_3072_raw_der_len = 398;	/* rsa_pub_3072_pcks_der_len - pcks_nr_1_header_len */

static tls_wrapper_err_t gen_rsa3072_key(wolfssl_ctx_t *ws_ctx, RsaKey *key,
					 uint8_t *priv_key_buf,
					 unsigned int *priv_key_len,
					 uint8_t *pub_key_buf,
					 unsigned int *pub_key_len)
{
	RNG rng;
	wc_InitRng(&rng);

	wc_InitRsaKey(key, 0);

	int ret = wc_MakeRsaKey(key, 3072, 65537, &rng);
	if (ret != 0) {
		ETLS_ERR("ERROR: generating private key\n");
		return -TLS_WRAPPER_ERR_PRIV_KEY;
	}

	uint8_t der[4096];
	int der_sz = wc_RsaKeyToDer(key, der, sizeof(der));
	if (der_sz < 0 || der_sz > *priv_key_len) {
		ETLS_ERR("ERROR: convert RsaKey key to DER format\n");
		return -TLS_WRAPPER_ERR_PRIV_KEY_LEN;
	}

	/* Expect a 3072 bit RSA key */
	if (key->n.used != 48 /* == 3072 / 8 / 8 */ ) {
		ETLS_ERR("ERROR: not a 3072 bit RSA key\n");
		return -TLS_WRAPPER_ERR_RSA_KEY_LEN;
	}

	/* SetRsaPublicKey() only exports n and e without wrapping them in
	   additional ASN.1 (PKCS#1). */
	uint8_t buf[1024];
	int pub_rsa_key_der_len = SetRsaPublicKey(buf, key, sizeof(buf), 0);
	if (pub_rsa_key_der_len != rsa_pub_3072_raw_der_len) {
		ETLS_ERR("ERROR: convert public key to DER format\n");
		return -TLS_WRAPPER_ERR_PUB_KEY_LEN;
	}
	*pub_key_len = pub_rsa_key_der_len;
	memcpy(pub_key_buf, buf, pub_rsa_key_der_len);

	*priv_key_len = der_sz;
	memcpy(priv_key_buf, der, der_sz);

	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t wolfssl_gen_pubkey_hash(tls_wrapper_ctx_t *ctx,
					  enclave_tls_cert_algo_t algo,
					  uint8_t *hash)
{
	ETLS_DEBUG("tls_wrapper_wolfssl gen_pubkey_hash is called\n");

	tls_wrapper_err_t err = TLS_WRAPPER_ERR_NONE;

	if (algo != ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
		return -TLS_WRAPPER_ERR_UNSUPPORTED_ALGO;

	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private;

	ws_ctx->priv_key_len = sizeof(ws_ctx->priv_key_buf);
	ws_ctx->pub_key_len = sizeof(ws_ctx->pub_key_buf);

	err = gen_rsa3072_key(ws_ctx, &ws_ctx->key, ws_ctx->priv_key_buf,
			      &ws_ctx->priv_key_len, ws_ctx->pub_key_buf,
			      &ws_ctx->pub_key_len);
	if (err != TLS_WRAPPER_ERR_NONE)
		return err;

	Sha256 sha256;
	wc_InitSha256(&sha256);
	wc_Sha256Update(&sha256, ws_ctx->pub_key_buf, ws_ctx->pub_key_len);
	wc_Sha256Final(&sha256, hash);

	return TLS_WRAPPER_ERR_NONE;
}
