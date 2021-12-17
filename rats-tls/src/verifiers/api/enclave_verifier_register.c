/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/verifier.h"
#include "internal/cpu.h"

enclave_verifier_err_t enclave_verifier_register(const enclave_verifier_opts_t *opts)
{
	if (!opts)
		return -ENCLAVE_VERIFIER_ERR_INVALID;

	RTLS_DEBUG("registering the enclave verifier '%s' ...\n", opts->name);

	enclave_verifier_opts_t *new_opts = (enclave_verifier_opts_t *)malloc(sizeof(*new_opts));
	if (!new_opts)
		return -ENCLAVE_VERIFIER_ERR_NO_MEM;

	memcpy(new_opts, opts, sizeof(*new_opts));

	if ((new_opts->name[0] == '\0') || (strlen(new_opts->name) >= sizeof(new_opts->name))) {
		RTLS_ERR("invalid enclave verifier name\n");
		goto err;
	}

	if (strlen(new_opts->type) >= sizeof(new_opts->type)) {
		RTLS_ERR("invalid enclave verifier type\n");
		goto err;
	}

	if (new_opts->api_version > ENCLAVE_VERIFIER_API_VERSION_MAX) {
		RTLS_ERR("unsupported enclave verifier api version %d > %d\n",
			 new_opts->api_version, ENCLAVE_VERIFIER_API_VERSION_MAX);
		goto err;
	}

	/* Default type equals to name */
	if (new_opts->type[0] == '\0')
		snprintf(new_opts->type, sizeof(new_opts->type), "%s", new_opts->name);

	enclave_verifiers_opts[registerd_enclave_verifier_nums++] = new_opts;

	RTLS_INFO("the enclave verifier '%s' registered with type '%s'\n", new_opts->name,
		  new_opts->type);

	return ENCLAVE_VERIFIER_ERR_NONE;

err:
	free(new_opts);
	return -ENCLAVE_VERIFIER_ERR_INVALID;
}
