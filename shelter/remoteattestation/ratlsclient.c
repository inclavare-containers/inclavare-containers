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
//#include "wolfssl/options.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#define DEFAULT_PORT 11111
#include <sgx_quote.h>
#include "ra.h"
#ifdef SGX_RATLS_MUTUAL
#include "ra-attester.h"
#endif
#include "ra-challenger.h"

static int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX * store)
{
	(void)preverify;

	int to_fd;
	int rett;
	to_fd = open("cert-elv.txt", O_WRONLY|O_CREAT, 0777);
	if(to_fd != -1)
		rett = write(to_fd, store->certs->buffer, store->certs->length);
	close(to_fd);
	fprintf(stdout, "start verify sgx cert.\n");
	int ret = verify_sgx_cert_extensions(store->certs->buffer,
					     store->certs->length);
	fprintf(stdout, "complete verify sgx cert.\n");
	fprintf(stderr, "Verifying SGX certificate extensions ... %s\n",
		ret == 0 ? "Success" : "Failure");
	return !ret;
}

#ifdef SGX_RATLS_MUTUAL
extern struct ra_tls_options my_ra_tls_options;
#endif

int ra_tls_echo(int sockfd, unsigned char* mrenclave, unsigned char* mrsigner)
{
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
	create_key_and_x509(key, &key_len, crt, &crt_len, &my_ra_tls_options);
	int ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, key_len,
						    SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);

	ret = wolfSSL_CTX_use_certificate_buffer(ctx, crt, crt_len,
						 SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);
#endif
	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cert_verify_callback);
	WOLFSSL *ssl = wolfSSL_new(ctx);
	if (!ssl) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
		goto err_ctx;
	}
	fprintf(stdout, "wolfSSL_CTX_set_verify success.\n");

	/* Attach wolfSSL to the socket */
	wolfSSL_set_fd(ssl, sockfd);

	if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
		fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
		goto err_ssl;
	}

	fprintf(stdout, "wolfSSL_connect success.\n");
	WOLFSSL_X509 *srvcrt = wolfSSL_get_peer_certificate(ssl);
	fprintf(stdout, "wolfSSL_get_peer_certificate success.\n");
	int derSz;
	const unsigned char *der = wolfSSL_X509_get_der(srvcrt, &derSz);
	fprintf(stdout, "wolfSSL_X509_get_der success.\n");

	sgx_quote_t quote;
	get_quote_from_cert(der, derSz, &quote);
	fprintf(stdout, "get_quote_from_cert success.\n");
	sgx_report_body_t *body = &quote.report_body;
	printf("  . MRENCLAVE  = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i){
		printf("%02x", body->mr_enclave.m[i]);
		mrenclave[i] = body->mr_enclave.m[i];
	}
	printf("\n");

	printf("  . MRSIGNER  = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i){
		printf("%02x", body->mr_signer.m[i]);
		mrsigner[i] = body->mr_signer.m[i];
	}
	printf("\n");

	const char *http_request = "GET / HTTP/1.0\r\n\r\n";
	size_t len = strlen(http_request);
	if (wolfSSL_write(ssl, http_request, len) != (int)len) {
		fprintf(stderr, "ERROR: failed to write\n");
		goto err_ssl;
	}

	char buff[256];
	memset(buff, 0, sizeof(buff));
	if (wolfSSL_read(ssl, buff, sizeof(buff) - 1) == -1) {
		fprintf(stderr, "ERROR: failed to read\n");
		goto err_ssl;
	}

err_ssl:
	wolfSSL_free(ssl);
err_ctx:
	wolfSSL_CTX_free(ctx);
err:
	wolfSSL_Cleanup();
	return 0;
}
