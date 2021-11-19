/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_VERIFIER_H
#define _INTERNAL_VERIFIER_H

#include <rats-tls/verifier.h>
#include "internal/core.h"

#define ENCLAVE_VERIFIERS_DIR "/usr/local/lib/rats-tls/verifiers/"

extern rats_tls_err_t rtls_enclave_verifier_load_all(void);
extern rats_tls_err_t rtls_enclave_verifier_load_single(const char *);
extern rats_tls_err_t rtls_verifier_select(rtls_core_context_t *, const char *,
					   rats_tls_cert_algo_t);
extern enclave_verifier_opts_t *enclave_verifiers_opts[ENCLAVE_VERIFIER_TYPE_MAX];
extern enclave_verifier_ctx_t *enclave_verifiers_ctx[ENCLAVE_VERIFIER_TYPE_MAX];
extern unsigned int enclave_verifier_nums;
extern unsigned int registerd_enclave_verifier_nums;

#endif
