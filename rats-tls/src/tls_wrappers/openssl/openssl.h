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

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/opensslv.h>

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

	RTLS_DEBUG("%s (err = %d)\n", buf, err);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
extern int X509_STORE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
#endif
#endif
