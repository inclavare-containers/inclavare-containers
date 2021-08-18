/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/verifier.h>

enclave_verifier_err_t nullverifier_pre_init(void)
{
	ETLS_DEBUG("called\n");

	return ENCLAVE_VERIFIER_ERR_NONE;
}
