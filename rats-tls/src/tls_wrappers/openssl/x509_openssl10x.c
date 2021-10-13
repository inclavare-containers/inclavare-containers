/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/x509.h>
#include <openssl/ssl.h>

int X509_STORE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, argl, argp, new_func, dup_func, free_func);
}

const STACK_OF(X509_EXTENSION) *X509_get0_extensions(const X509 *x)
{
    return x->cert_info->extensions;
}

int X509_STORE_set_ex_data(X509_STORE *ctx, int idx, void *data)
{
    return CRYPTO_set_ex_data(&ctx->ex_data, idx, data);
}

void *X509_STORE_get_ex_data(const X509_STORE *ctx, int idx)
{
    return CRYPTO_get_ex_data(&ctx->ex_data, idx);
}

X509_STORE *X509_STORE_CTX_get0_store(X509_STORE_CTX *ctx)
{
    return ctx->ctx;
}

#endif
