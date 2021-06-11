/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../wolfssl/oid.c"
#include "../wolfssl/un_negotiate.c"

int ocall_verify_certificate(uint8_t *der_crt, uint32_t der_crt_len)
{
	ETLS_DEBUG("der_crt  %p, der_crt_len %d\n", der_crt, der_crt_len);
	return verify_certificate(der_crt, der_crt_len);
}
