/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "openssl.h"

static int x509_extension_add(X509 *cert, const char *oid,
			const void *data, size_t data_len)
{
	int nid;
	ASN1_OCTET_STRING *octet = NULL;
	X509_EXTENSION *ext = NULL;
	int ret = -1;

	nid = OBJ_create(oid, NULL, NULL);
	if (nid == NID_undef) {
		ETLS_DEBUG("obj create failed, %s\n", oid);
		return ret;
	}

	octet = ASN1_OCTET_STRING_new();
	if (!octet)
		goto err;

	ASN1_OCTET_STRING_set(octet, data, data_len);

	ext = X509_EXTENSION_create_by_NID(NULL, nid, 0, octet);
	if (!ext) {
		ETLS_DEBUG("extension create failed, %s\n", oid);
		goto err;
	}

	if (!X509_add_ext(cert, ext, -1)) {
		ETLS_DEBUG("extension add failed, %s\n", oid);
		goto err;
	}

	ret = 0;

err:
	ETLS_DEBUG("X509 extension add failed, %s, nid = %d\n", oid, nid);

	if (ext)
		X509_EXTENSION_free(ext);

	if (octet)
		ASN1_OCTET_STRING_free(octet);

	return ret;
}

crypto_wrapper_err_t openssl_gen_cert(crypto_wrapper_ctx_t *ctx,
 			       enclave_tls_cert_info_t *cert_info)
{
	struct openssl_ctx *octx;
	cert_subject_t *subject;
	X509 *cert = NULL;
	X509_NAME *name;
	EVP_PKEY *pkey = NULL;
	unsigned char *der;
	int len;
	int ret;

	ETLS_DEBUG("ctx %p, cert_info %p\n", ctx, cert_info);

	if (!ctx || !cert_info)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	octx = ctx->crypto_private;

	pkey = EVP_PKEY_new();
	if (!pkey)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	ret = -CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;
	if (!EVP_PKEY_assign_RSA(pkey, octx->key))
		goto err;

	ret = -CRYPTO_WRAPPER_ERR_NO_MEM;
	cert = X509_new();
	if (!cert)
		goto err;

	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 9527);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	/* 10 years */
	X509_gmtime_adj(X509_get_notAfter(cert), 3600 * 24 * 365 * 10);

	ret = -CRYPTO_WRAPPER_ERR_PUB_KEY_LEN;
	if (!X509_set_pubkey(cert, pkey))
		goto err;

	/* subject name */
	name = X509_get_subject_name(cert);
	if (!name)
		goto err;

	subject = &cert_info->subject;
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
			subject->organization, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
			subject->organization_unit, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
			subject->common_name, -1, -1, 0);
	if (!X509_set_issuer_name(cert, name))
		goto err;

	ret = -CRYPTO_WRAPPER_ERR_PUB_KEY_DECODE;

	ETLS_DEBUG("evidence type '%s' requested\n", cert_info->evidence.type);

	if (strcmp(cert_info->evidence.type, "sgx_epid") == 0) {
		attestation_verification_report_t *epid = &cert_info->evidence.epid;

		x509_extension_add(cert, "1.2.840.113741.1337.2",
				epid->ias_report, epid->ias_report_len);
		x509_extension_add(cert, "1.2.840.113741.1337.3",
				epid->ias_sign_ca_cert, epid->ias_sign_ca_cert_len);
		x509_extension_add(cert, "1.2.840.113741.1337.4",
				epid->ias_sign_cert, epid->ias_sign_cert_len);
		x509_extension_add(cert, "1.2.840.113741.1337.5",
				epid->ias_report_signature, epid->ias_report_signature_len);
	} else if (strcmp(cert_info->evidence.type, "sgx_ecdsa") == 0) {
		ecdsa_attestation_evidence_t *ecdsa = &cert_info->evidence.ecdsa;

		x509_extension_add(cert, "1.2.840.113741.1337.6",
				ecdsa->quote, ecdsa->quote_len);
	} else if (strcmp(cert_info->evidence.type, "sgx_la") == 0) {
		la_attestation_evidence_t *la = &cert_info->evidence.la;

		x509_extension_add(cert, "1.2.840.113741.1337.14",
				la->report, la->report_len);
	}

	ret = -CRYPTO_WRAPPER_ERR_CERT;
	if (!X509_sign(cert, pkey, EVP_sha256()))
		goto err;

	der = cert_info->cert_buf;
	len = i2d_X509(cert, &der);
	if (len < 0)
		goto err;

	cert_info->cert_len = len;

	ETLS_DEBUG("self-signing certificate generated\n");

	ret = CRYPTO_WRAPPER_ERR_NONE;

err:
	if (ret != CRYPTO_WRAPPER_ERR_NONE)
		ETLS_DEBUG("failed to generate certificate %d\n", ret);

	if (cert)
		X509_free(cert);

	if (pkey)
		EVP_PKEY_free(pkey);

	return ret;
}
