/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>

enclave_verifier_err_t sgx_ecdsa_verifier_pre_init(void)
{
	RTLS_DEBUG("called\n");

	return ENCLAVE_VERIFIER_ERR_NONE;
}
