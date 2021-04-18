/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <enclave-tls/err.h>
#include <enclave-tls/log.h>
#include "internal/crypto_wrapper.h"

crypto_wrapper_err_t crypto_wrapper_register(const crypto_wrapper_opts_t *opts)
{
	if (!opts)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	ETLS_DEBUG("registering the crypto wrapper '%s' ...\n", opts->type);

	crypto_wrapper_opts_t *new_opts =
		(crypto_wrapper_opts_t *)malloc(sizeof(*new_opts));
	if (!new_opts)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	memcpy(new_opts, opts, sizeof(*new_opts));

	if (new_opts->type[0] == '\0') {
		ETLS_ERR("invalid crypto wrapper type\n");
		goto err;
	}

	if (new_opts->api_version > CRYPTO_WRAPPER_API_VERSION_MAX) {
		ETLS_ERR("unsupported crypto wrapper api version %d > %d\n",
			 new_opts->api_version, CRYPTO_WRAPPER_API_VERSION_MAX);
		goto err;
	}

	crypto_wrappers_opts[registerd_crypto_wrapper_nums++] = new_opts;

	ETLS_INFO("the crypto wrapper '%s' registered\n", opts->type);

	return CRYPTO_WRAPPER_ERR_NONE;

err:
	free(new_opts);
	return -CRYPTO_WRAPPER_ERR_INVALID;
}
