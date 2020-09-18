/* ra-tls-server.c
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

#include "ra-tls-server.h"

/* the usual suspects */
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <wolfssl/ssl.h>
#include <wolfssl/certs_test.h>

#define DEFAULT_PORT 11111

#define CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"

int ra_tls_server_startup(sgx_enclave_id_t id, int connd)
{
#ifdef SGX_DEBUG
	enc_wolfSSL_Debugging_ON(id);
#else
	enc_wolfSSL_Debugging_OFF(id);
#endif

	int sgxStatus;
	enc_wolfSSL_Init(id, &sgxStatus);

	WOLFSSL_METHOD *method;
	sgxStatus = enc_wolfTLSv1_2_server_method(id, &method);
	if (sgxStatus != SGX_SUCCESS || !method)
		return -1;

	WOLFSSL_CTX *ctx;
	sgxStatus = enc_wolfSSL_CTX_new(id, &ctx, method);
	if (sgxStatus != SGX_SUCCESS || !ctx)
		goto err;

	sgxStatus = enc_create_key_and_x509(id, ctx);
	assert(sgxStatus == SGX_SUCCESS);

	WOLFSSL *ssl;
	sgxStatus = enc_wolfSSL_new(id, &ssl, ctx);
	if (sgxStatus != SGX_SUCCESS || !ssl)
		goto err;

	/* Attach wolfSSL to the socket */
	int ret;
	sgxStatus = enc_wolfSSL_set_fd(id, &ret, ssl, connd);
	if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS)
		goto err_ssl;

	printf("Client connected successfully\n");

	char buff[256];
	size_t len;
	memset(buff, 0, sizeof(buff));
	sgxStatus = enc_wolfSSL_read(id, &ret, ssl, buff, sizeof(buff) - 1);
	if (sgxStatus != SGX_SUCCESS || ret == -1)
		goto err_ssl;

	printf("Client: %s\n", buff);

	/* Write our reply into buff */
	memset(buff, 0, sizeof(buff));
	memcpy(buff, "I hear ya fa shizzle!\n", sizeof(buff));
	len = strnlen(buff, sizeof(buff));

	/* Reply back to the client */
	sgxStatus = enc_wolfSSL_write(id, &ret, ssl, buff, len);
	if (sgxStatus != SGX_SUCCESS || ret != len)
		ret = -1;

      err_ssl:
	enc_wolfSSL_free(id, ssl);
      err_ctx:
	sgxStatus = enc_wolfSSL_CTX_free(id, ctx);
      err:
	sgxStatus = enc_wolfSSL_Cleanup(id, &ret);

	return ret;
}
