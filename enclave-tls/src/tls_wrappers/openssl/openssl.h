/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
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

static inline void print_openssl_err(SSL *ssl, int ret)
{
	char buf[128];
	int err = SSL_get_error(ssl, ret);
	ERR_error_string((unsigned long)err, buf);

	ETLS_DEBUG("%s (err = %d)\n", buf, err);
}
#endif
