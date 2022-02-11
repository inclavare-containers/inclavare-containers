/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_CORE_H
#define _INTERNAL_CORE_H

// clang-format off
#include <sys/types.h>
#include <rats-tls/attester.h>
#include <rats-tls/verifier.h>
#include <rats-tls/tls_wrapper.h>
#include <rats-tls/crypto_wrapper.h>
#include <rats-tls/api.h>
#ifdef SGX
#include "rtls_syscalls.h"
#endif
// clang-format on

typedef struct rtls_core_context_t {
	rats_tls_conf_t config;
	unsigned long flags;
	rats_tls_callback_t user_callback;
	enclave_attester_ctx_t *attester;
	enclave_verifier_ctx_t *verifier;
	tls_wrapper_ctx_t *tls_wrapper;
	crypto_wrapper_ctx_t *crypto_wrapper;
} rtls_core_context_t;

#ifdef SGX
typedef struct ocall_dirent rtls_dirent;
#else
typedef struct dirent rtls_dirent;
#endif

extern rtls_core_context_t global_core_context;

extern rats_tls_err_t rtls_core_generate_certificate(rtls_core_context_t *);

extern void rtls_exit(void);

extern rats_tls_log_level_t rtls_loglevel_getenv(const char *name);

extern rats_tls_err_t rtls_instance_init(const char *type, const char *realpath, void **handle);

extern ssize_t rtls_write(int fd, const void *buf, size_t count);

extern ssize_t rtls_read(int fd, void *buf, size_t count);

extern uint64_t rtls_opendir(const char *name);

extern int rtls_readdir(uint64_t dirp, rtls_dirent **ptr);

extern int rtls_closedir(uint64_t dir);

// Whether the quote instance is initialized
#define RATS_TLS_CTX_FLAGS_QUOTING_INITIALIZED (1 << 0)
// Whether the tls lib is initialized
#define RATS_TLS_CTX_FLAGS_TLS_INITIALIZED (1 << 16)
// Whether the tls library has completed the creation and initialization of the TLS certificate
#define RATS_TLS_CTX_FLAGS_CERT_CREATED (1 << 17)
// Whether the crypto lib is initialized
#define RATS_TLS_CTX_FLAGS_CRYPTO_INITIALIZED (1 << 18)

#endif
