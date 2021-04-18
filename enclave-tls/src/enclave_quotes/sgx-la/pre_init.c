/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>

enclave_quote_err_t sgx_la_pre_init(void)
{
	ETLS_DEBUG("called\n");

	return ENCLAVE_QUOTE_ERR_NONE;
}
