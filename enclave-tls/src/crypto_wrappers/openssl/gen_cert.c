/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/oid.h>
#include "openssl.h"

#define CERT_SERIAL_NUMBER 9527

static int x509_extension_add(X509 *cert, const char *oid, const void *data, size_t data_len)
{
	int nid;
	ASN1_OCTET_STRING *octet = NULL;
	X509_EXTENSION *ext = NULL;
	int ret = 0;

	nid = OBJ_txt2nid(oid);
	if (nid == NID_undef) {
		nid = OBJ_create(oid, NULL, NULL);
		if (nid == NID_undef) {
			ETLS_DEBUG("failed to create the object %s\n", oid);
			return ret;
		}
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

	ret = 1;

err:
	if (ret == 0)
		ETLS_DEBUG("X509 extension add failed, %s, nid = %d\n", oid, nid);

	if (ext)
		X509_EXTENSION_free(ext);

	if (octet)
		ASN1_OCTET_STRING_free(octet);

	return ret;
}

crypto_wrapper_err_t openssl_gen_cert(crypto_wrapper_ctx_t *ctx, enclave_tls_cert_algo_t algo,
				      enclave_tls_cert_info_t *cert_info)
{
	openssl_ctx *octx = NULL;
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

	if (algo == ENCLAVE_TLS_CERT_ALGO_ECC_256_SHA256) {
		if (!EVP_PKEY_assign_EC_KEY(pkey, octx->eckey))
			goto err;
	} else if (algo == ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256) {
		if (!EVP_PKEY_assign_RSA(pkey, octx->key))
			goto err;
	} else {
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	ret = -CRYPTO_WRAPPER_ERR_NO_MEM;
	cert = X509_new();
	if (!cert)
		goto err;

	X509_set_version(cert, 3);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), CERT_SERIAL_NUMBER);
	/* 0 indicate start from the current time */
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
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, subject->organization, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, subject->organization_unit, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, subject->common_name, -1, -1, 0);
	if (!X509_set_issuer_name(cert, name))
		goto err;

	ret = -CRYPTO_WRAPPER_ERR_PUB_KEY_DECODE;

	ETLS_DEBUG("evidence type '%s' requested\n", cert_info->evidence.type);

	if (!strcmp(cert_info->evidence.type, "sgx_epid")) {
		attestation_verification_report_t *epid = &cert_info->evidence.epid;

		if (!x509_extension_add(cert, ias_response_body_oid, epid->ias_report,
					epid->ias_report_len))
			goto err;

		if (!x509_extension_add(cert, ias_root_cert_oid, epid->ias_sign_ca_cert,
					epid->ias_sign_ca_cert_len))
			goto err;

		if (!x509_extension_add(cert, ias_leaf_cert_oid, epid->ias_sign_cert,
					epid->ias_sign_cert_len))
			goto err;

		if (!x509_extension_add(cert, ias_report_signature_oid, epid->ias_report_signature,
					epid->ias_report_signature_len))
			goto err;
	} else if (!strcmp(cert_info->evidence.type, "sgx_ecdsa")) {
		ecdsa_attestation_evidence_t *ecdsa = &cert_info->evidence.ecdsa;

		if (!x509_extension_add(cert, ecdsa_quote_oid, ecdsa->quote, ecdsa->quote_len))
			goto err;
	} else if (!strcmp(cert_info->evidence.type, "sgx_la")) {
		la_attestation_evidence_t *la = &cert_info->evidence.la;

		if (!x509_extension_add(cert, la_report_oid, la->report, la->report_len))
			goto err;
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
