/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave/err.h>
#include <rats-tls/tls_wrapper.h>

tls_wrapper_err_t ocall_openssl_lib_init()
{
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	if (SSL_library_init() < 0) {
		RTLS_ERR("failed to initialize the openssl library\n");
		return -TLS_WRAPPER_ERR_NOT_FOUND;
	}

	return TLS_WRAPPER_ERR_NONE;
}
