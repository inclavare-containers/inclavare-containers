/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_CRYPTO_WRAPPER_H
#define _INTERNAL_CRYPTO_WRAPPER_H

#include <rats-tls/crypto_wrapper.h>
#include "internal/core.h"

#define CRYPTO_WRAPPERS_DIR "/usr/local/lib/rats-tls/crypto-wrappers/"

extern rats_tls_err_t rtls_crypto_wrapper_load_all(void);
extern rats_tls_err_t rtls_crypto_wrapper_load_single(const char *);
extern rats_tls_err_t rtls_crypto_wrapper_select(rtls_core_context_t *, const char *);

extern crypto_wrapper_ctx_t *crypto_wrappers_ctx[CRYPTO_WRAPPER_TYPE_MAX];
extern crypto_wrapper_opts_t *crypto_wrappers_opts[CRYPTO_WRAPPER_TYPE_MAX];
extern unsigned int crypto_wrappers_nums;
extern unsigned registerd_crypto_wrapper_nums;

#endif
