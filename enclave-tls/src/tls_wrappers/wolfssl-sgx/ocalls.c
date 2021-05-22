/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include "../wolfssl/oid.c"
#include "../wolfssl/un_negotiate.c"

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
	return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
	return send(sockfd, buf, len, flags);
}

int ocall_verify_certificate(void *ctx, uint8_t *der_crt, uint32_t der_crt_len)
{
	ETLS_DEBUG("ctx %p, der_crt %p, der_crt_len %d\n", ctx, der_crt, der_crt_len);
	return verify_certificate(ctx, der_crt, der_crt_len);
}
