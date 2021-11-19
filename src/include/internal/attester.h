/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_ATTESTER_H
#define _INTERNAL_ATTESTER_H

#include <rats-tls/attester.h>
#include "internal/core.h"

#define ENCLAVE_ATTESTERS_DIR "/usr/local/lib/rats-tls/attesters/"

extern rats_tls_err_t rtls_enclave_attester_load_all(void);
extern rats_tls_err_t rtls_enclave_attester_load_single(const char *);
extern rats_tls_err_t rtls_attester_select(rtls_core_context_t *, const char *,
					   rats_tls_cert_algo_t);
extern enclave_attester_opts_t *enclave_attesters_opts[ENCLAVE_ATTESTER_TYPE_MAX];
extern enclave_attester_ctx_t *enclave_attesters_ctx[ENCLAVE_ATTESTER_TYPE_MAX];
extern unsigned int enclave_attester_nums;
extern unsigned int registerd_enclave_attester_nums;

#endif
