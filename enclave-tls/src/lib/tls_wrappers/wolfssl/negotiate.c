#define _GNU_SOURCE
#include <string.h>
#include <assert.h>
#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl_private.h"

const int rsa_pub_3072_raw_der_len = 398;	/* rsa_pub_3072_pcks_der_len - pcks_nr_1_header_len */

/**
 * @return Returns -1 if OID was not found. Otherwise, returns 1;
 */
int find_oid(const unsigned char *ext, size_t ext_len,
	     const unsigned char *oid, size_t oid_len,
	     unsigned char **val, size_t *len)
{
	uint8_t *p = memmem(ext, ext_len, oid, oid_len);

	if (!p)
		return -1;

	p += oid_len;

	int i = 0;

	// Some TLS libraries generate a BOOLEAN for the criticality of the extension.
	if (p[i] == 0x01) {
		assert(p[i++] == 0x01);	// tag, 0x01 is ASN1 Boolean
		assert(p[i++] == 0x01);	// length
		assert(p[i++] == 0x00);	// value (0 is non-critical, non-zero is critical)
	}

	// Now comes the octet string
	assert(p[i++] == 0x04);	// tag for octet string
	assert(p[i++] == 0x82);	// length encoded in two bytes
	*len = p[i++] << 8;
	*len += p[i++];
	*val = &p[i++];

	return 1;
}

/**
 * @return Returns -1 if OID was not found. Otherwise, returns 1;
 */
/* *INDENT-OFF* */
int extract_x509_extension(const uint8_t *ext, int ext_len,
			   const uint8_t *oid, size_t oid_len, uint8_t *data,
			   uint32_t *data_len, uint32_t data_max_len)
{
	uint8_t *ext_data;
	size_t ext_data_len;

	int rc = find_oid(ext, ext_len, oid, oid_len, &ext_data, &ext_data_len);
	if (rc == -1 || ext_data == NULL || ext_data_len > data_max_len)
		return -1;

	memcpy(data, ext_data, (uint32_t)ext_data_len);
	*data_len = (uint32_t)ext_data_len;

	return 1;
}

/**
 * Extract all extensions.
 * @return Returns -1 if OID was not found. Otherwise, returns 1;
 */
static int extract_cert_extensions(const uint8_t *ext, int ext_len,
				   attestation_evidence_t *evidence)
{
	if (!strcmp(evidence->type, "sgx-epid")) {
		int rc = extract_x509_extension(ext, ext_len,
						ias_response_body_oid,
						ias_oid_len,
						evidence->epid.ias_report,
						&evidence->epid.ias_report_len,
						sizeof(evidence->epid.ias_report));
		if (rc != 1)
			return rc;

		rc = extract_x509_extension(ext, ext_len,
					    ias_root_cert_oid, ias_oid_len,
					    evidence->epid.ias_sign_ca_cert,
					    &evidence->epid.
					    ias_sign_ca_cert_len,
					    sizeof(evidence->epid.ias_sign_ca_cert));
		if (rc != 1)
			return rc;

		rc = extract_x509_extension(ext, ext_len,
					    ias_leaf_cert_oid, ias_oid_len,
					    evidence->epid.ias_sign_cert,
					    &evidence->epid.ias_sign_cert_len,
					    sizeof(evidence->epid.ias_sign_cert));
		if (rc != 1)
			return rc;

		rc = extract_x509_extension(ext, ext_len,
					    ias_report_signature_oid,
					    ias_oid_len,
					    evidence->epid.ias_report_signature,
					    &evidence->epid.
					    ias_report_signature_len,
					    sizeof(evidence->epid.ias_report_signature));
		return rc;
	} else if (!strcmp(evidence->type, "sgx-ecdsa")) {
		/* Compatible with extension data length to avoid copy buffer overflow */
		uint8_t report[8192];
		uint32_t report_len;
		return extract_x509_extension(ext, ext_len,
					      quote_oid, ias_oid_len,
					      report, &report_len,
					      sizeof(report));
	} else if (!strcmp(evidence->type, "sgx-la")) {
		/* FIXME: need to add extract_x509_extension form sgx la report */
		/* TODO */
	}

	return 1;
}

crypto_wrapper_err_t sha256_rsa_pubkey(unsigned char hash[SHA256_DIGEST_SIZE],
				       RsaKey *key)
{
	uint8_t buf[1024];

	/* SetRsaPublicKey() only exports n and e without wrapping them in
	   additional ASN.1 (PKCS#1). */
	int pub_rsa_key_der_len = SetRsaPublicKey(buf, key, sizeof(buf), 0);
	if (pub_rsa_key_der_len != rsa_pub_3072_raw_der_len)
		return -CRYPTO_WRAPPER_ERR_PUB_KEY_LEN;

	Sha256 sha;
	wc_InitSha256(&sha);
	wc_Sha256Update(&sha, buf, pub_rsa_key_der_len);
	wc_Sha256Final(&sha, hash);

	return CRYPTO_WRAPPER_ERR_NONE;
}

static crypto_wrapper_err_t calc_pubkey_hash(DecodedCert *crt,
					     enclave_tls_cert_algo_t algo,
					     uint8_t *hash)
{
	if (algo != ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;

	RsaKey rsaKey;
	wc_InitRsaKey(&rsaKey, NULL);

	unsigned int idx = 0;
	int ret = wc_RsaPublicKeyDecode(crt->publicKey, &idx, &rsaKey,
					crt->pubKeySize);
	if (ret)
		return WOLFCRYPT_ERR_CODE(ret);

	crypto_wrapper_err_t err = sha256_rsa_pubkey(hash, &rsaKey);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		return err;

	wc_FreeRsaKey(&rsaKey);

	return CRYPTO_WRAPPER_ERR_NONE;
}

static int verify_certificate(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
	(void) preverify;

	ETLS_DEBUG("preverify %d, store %p\n", preverify, store);

	const uint8_t *der_cert = store->certs->buffer;
	uint32_t der_cert_len = store->certs->length;

	DecodedCert crt;
	InitDecodedCert(&crt, der_cert, der_cert_len, NULL);

	int ret = ParseCert(&crt, CERT_TYPE, NO_VERIFY, 0);
	if (ret) {
		ETLS_DEBUG("ParseCertRelative error with code %d\n", ret);
		return 0;
	}

	tls_wrapper_ctx_t *tls_ctx = (tls_wrapper_ctx_t *)store->userCtx;

	/* FIXME: add the ability to define different hash_size acording to cert_algo */
	enclave_tls_cert_algo_t cert_algo = ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256;
	unsigned int hash_size;
	if (cert_algo == ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
		hash_size = SHA256_HASH_SIZE;
	else
		return 0;

	uint8_t hash[hash_size];
	calc_pubkey_hash(&crt, cert_algo, hash);

	/* Extract the Enclave TLS certificate extension from the TLS certificate
	 * extension and parse it into evidence
	 */
	attestation_evidence_t evidence;
	int rc = extract_cert_extensions(crt.extensions, crt.extensionsSz,
					 &evidence);
	if (rc != 1) {
		ETLS_ERR("ERROR: extract_cert_extensions\n");
		return 0;
	}

	tls_wrapper_err_t err = tls_wrapper_verify_certificate_extension(tls_ctx, &evidence, hash);
	if (err != TLS_WRAPPER_ERR_NONE) {
		ETLS_ERR("failed to verify certificate extension %#x\n", err);
		return 0;
	}

	FreeDecodedCert(&crt);

	ETLS_DEBUG("Verifying certificate extensions ...%s\n",
		   ret == 0 ? "Success" : "Failure");

	return !ret;
}

tls_wrapper_err_t wolfssl_internal_negotiate(wolfssl_ctx_t *ws_ctx,
					     unsigned long conf_flags, int fd,
					     int (*verify)(int, WOLFSSL_X509_STORE_CTX *))
{
	if (verify)
		wolfSSL_CTX_set_verify(ws_ctx->ws, SSL_VERIFY_PEER, verify);

	ws_ctx->ssl = wolfSSL_new(ws_ctx->ws);
	if (!ws_ctx->ssl)
		return -TLS_WRAPPER_ERR_UNKNOWN;

	/* Attach wolfSSL to the socket */
	wolfSSL_set_fd(ws_ctx->ssl, fd);

	int err;
	if (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
		err = wolfSSL_negotiate(ws_ctx->ssl);
	else
		err = wolfSSL_connect(ws_ctx->ssl);

	if (err != SSL_SUCCESS) {
		if (conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER)
			ETLS_DEBUG("failed to negotiate %#x\n", err);
		else
			ETLS_DEBUG("failed to connect %#x\n", err);

		return WOLFSSL_ERR_CODE(err);
	}

	return TLS_WRAPPER_ERR_NONE;
}

tls_wrapper_err_t wolfssl_negotiate(tls_wrapper_ctx_t *ctx, int fd)
{
	ETLS_DEBUG("ctx %p, fd %d\n", ctx, fd);

	int (*verify)(int, WOLFSSL_X509_STORE_CTX *) = NULL;

	unsigned long conf_flags = ctx->conf_flags;

	if (!(conf_flags & ENCLAVE_TLS_CONF_FLAGS_SERVER))
		verify = verify_certificate;

	wolfssl_ctx_t *ws_ctx = (wolfssl_ctx_t *)ctx->tls_private;

	return wolfssl_internal_negotiate(ws_ctx, conf_flags, fd, verify);
}
/* *INDENT-ON* */
