/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _OPENSSL_PRIVATE_H
#define _OPENSSL_PRIVATE_H

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/ossl_typ.h>

#define SSL_SUCCESS 1

extern int openssl_extract_x509_extensions(X509 *crt, attestation_evidence_t *evidence);

typedef struct {
	SSL_CTX *sctx;
	SSL *ssl;
} openssl_ctx_t;

#define ias_response_body_oid	 "1.2.840.113741.1337.2"
#define ias_root_cert_oid	 "1.2.840.113741.1337.3"
#define ias_leaf_cert_oid	 "1.2.840.113741.1337.4"
#define ias_report_signature_oid "1.2.840.113741.1337.5"
#define ecdsa_quote_oid		 "1.2.840.113741.1337.6"
#define la_report_oid		 "1.2.840.113741.1337.14"

static inline void print_openssl_err(SSL *ssl, int ret)
{
	char buf[128];
	int err = SSL_get_error(ssl, ret);
	ERR_error_string((unsigned long)err, buf);

	ETLS_DEBUG("%s (err = %d)\n", buf, err);
}
#endif
