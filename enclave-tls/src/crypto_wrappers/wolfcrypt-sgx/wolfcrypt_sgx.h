/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _WOLFCRYPT_SGX_H
#define _WOLFCRYPT_SGX_H

#include <enclave-tls/api.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/signature.h>
#include "sgx_stub_u.h"

typedef struct {
	RsaKey key;
	unsigned int privkey_len;
	uint8_t privkey_buf[2048];
} wolfcrypt_sgx_ctx_t;

#endif
