/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/attester.h>

enclave_attester_err_t sgx_la_attester_pre_init(void)
{
	RTLS_DEBUG("called\n");

	return ENCLAVE_ATTESTER_ERR_NONE;
}
