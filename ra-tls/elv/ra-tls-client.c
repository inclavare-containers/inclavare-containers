/* client-tls.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* the usual suspects */
#ifdef SGX_RATLS_MUTUAL
#include <assert.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/ssl.h>

#define DEFAULT_PORT 11111

#include <sgx_quote.h>
#ifdef RATLS_ECDSA
#include <sgx_quote_3.h>
#endif
#include <sgx_urts.h>

#include "ra.h"
#ifdef SGX_RATLS_MUTUAL
#include "ra-attester.h"
#endif
#include "ra-challenger.h"

/* only for lareport */
/* TODO: This global variable is referenced in the underlying library */
sgx_enclave_id_t g_eid = -1;

static sgx_enclave_id_t load_enclave(void)
{
        sgx_launch_token_t t;
        memset(t, 0, sizeof(t));

        sgx_enclave_id_t id;
        int updated = 0;
        int ret = sgx_create_enclave("Wolfssl_Enclave.signed.so", 1, &t, &updated, &id, NULL);
        if (ret != SGX_SUCCESS) {
                fprintf(stderr, "Failed to create Enclave: error %d\n", ret);
				exit(EXIT_FAILURE);
        }

        return id;
}

static int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX * store)
{
	(void)preverify;
	int ret = verify_sgx_cert_extensions(store->certs->buffer,
					     store->certs->length);

	fprintf(stderr, "Verifying SGX certificate extensions ... %s\n",
		ret == 0 ? "Success" : "Failure");
	return !ret;
}

#ifdef SGX_RATLS_MUTUAL
extern struct ra_tls_options my_ra_tls_options;
#endif

int ra_tls_send(int sockfd, const void *bufsnd, size_t sz_bufsnd,
		void *bufrcv, size_t sz_bufrcv,
		unsigned char mrenclave[SGX_HASH_SIZE],
		unsigned char mrsigner[SGX_HASH_SIZE])
{
	int ret = -1;
	wolfSSL_Debugging_ON();

	wolfSSL_Init();

	WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!ctx) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
		goto err;
	}

#ifdef SGX_RATLS_MUTUAL
	uint8_t key[2048];
	uint8_t crt[8192];
	int key_len = sizeof(key);
	int crt_len = sizeof(crt);

#ifdef RATLS_ECDSA
	ecdsa_create_key_and_x509(key, &key_len, crt, &crt_len);
#else
	create_key_and_x509(key, &key_len, crt, &crt_len, &my_ra_tls_options);
#endif

	int ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, key_len,
						    SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);

	ret = wolfSSL_CTX_use_certificate_buffer(ctx, crt, crt_len,
						 SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);
#endif

#ifdef LA_REPORT
	g_eid = load_enclave();
#endif

	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cert_verify_callback);

	WOLFSSL *ssl = wolfSSL_new(ctx);
	if (!ssl) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
		goto err_ctx;
	}

	/* Attach wolfSSL to the socket */
	wolfSSL_set_fd(ssl, sockfd);

	if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
		fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
		goto err_ssl;
	}

	WOLFSSL_X509 *srvcrt = wolfSSL_get_peer_certificate(ssl);

	int derSz;
	const unsigned char *der = wolfSSL_X509_get_der(srvcrt, &derSz);
	sgx_report_body_t *body = NULL;

#ifdef RATLS_ECDSA
	uint8_t quote_buff[8192] = {0,};
	ecdsa_get_quote_from_dcap_cert(der, derSz, (sgx_quote3_t*)quote_buff);
	sgx_quote3_t* quote = (sgx_quote3_t*)quote_buff;
	body = &quote->report_body;
	printf("ECDSA verification\n");
#elif defined LA_REPORT
        sgx_report_t report = {0,};
        la_get_report_from_cert(der, derSz, &report);
        body = &report.body;
        printf("Local report verification\n");
#else
	uint8_t quote_buff[8192] = {0,};
	get_quote_from_cert(der, derSz, (sgx_quote_t*)quote_buff);
	sgx_quote_t* quote = (sgx_quote_t*)quote_buff;
	body = &quote->report_body;
	printf("EPID verification\n");
#endif

	printf("Server's SGX identity:\n");
	printf("  . MRENCLAVE = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i) {
		printf("%02x", body->mr_enclave.m[i]);
	}
	printf("\n");
	printf("  . MRSIGNER  = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i) {
		printf("%02x", body->mr_signer.m[i]);
	}
	printf("\n");

	if (mrenclave)
		memcpy(mrenclave, body->mr_enclave.m, SGX_HASH_SIZE);
	if (mrsigner)
		memcpy(mrsigner, body->mr_enclave.m, SGX_HASH_SIZE);

	if (wolfSSL_write(ssl, bufsnd, sz_bufsnd) != (int)sz_bufsnd) {
		fprintf(stderr, "ERROR: failed to write\n");
		goto err_ssl;
	}
	ret = wolfSSL_read(ssl, bufrcv, sz_bufrcv);
	if (ret == -1) {
		fprintf(stderr, "ERROR: failed to read\n");
		goto err_ssl;
	}
err_ssl:
	wolfSSL_free(ssl);
err_ctx:
	wolfSSL_CTX_free(ctx);
err:
	wolfSSL_Cleanup();

	return ret;
}

int ra_tls_echo(int sockfd)
{
	char buffer[256];
	const char *http_request = "GET / HTTP/1.0\r\n\r\n";
	size_t len = strlen(http_request);

	memset(buffer, 0, sizeof(buffer));
	ra_tls_send(sockfd, http_request, len, buffer, sizeof(buffer), NULL, NULL);
	printf("Server:\n%s\n", buffer);

	return 0;
}
