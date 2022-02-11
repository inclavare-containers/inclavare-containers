/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/attester.h"
#include "internal/cpu.h"

enclave_attester_err_t enclave_attester_register(const enclave_attester_opts_t *opts)
{
	if (!opts)
		return -ENCLAVE_ATTESTER_ERR_INVALID;

	RTLS_DEBUG("registering the enclave attester '%s' ...\n", opts->name);

	if (opts->flags & ENCLAVE_ATTESTER_OPTS_FLAGS_TDX_GUEST) {
		if (!is_tdguest_supported()) {
			// clang-format off
			RTLS_DEBUG("failed to register the attester '%s' due to lack of TDX Guest capability\n",
				   opts->type);
			// clang-format on
			return -ENCLAVE_ATTESTER_ERR_CPU_UNSUPPORTED;
		}
	}

	enclave_attester_opts_t *new_opts = (enclave_attester_opts_t *)malloc(sizeof(*new_opts));
	if (!new_opts)
		return -ENCLAVE_ATTESTER_ERR_NO_MEM;

	memcpy(new_opts, opts, sizeof(*new_opts));

	if ((new_opts->name[0] == '\0') || (strlen(new_opts->name) >= sizeof(new_opts->name))) {
		RTLS_ERR("invalid enclave attester name\n");
		goto err;
	}

	if (strlen(new_opts->type) >= sizeof(new_opts->type)) {
		RTLS_ERR("invalid enclave attester type\n");
		goto err;
	}

	if (new_opts->api_version > ENCLAVE_ATTESTER_API_VERSION_MAX) {
		RTLS_ERR("unsupported enclave attester api version %d > %d\n",
			 new_opts->api_version, ENCLAVE_ATTESTER_API_VERSION_MAX);
		goto err;
	}

	/* Default type equals to name */
	if (new_opts->type[0] == '\0')
		snprintf(new_opts->type, sizeof(new_opts->type), "%s", new_opts->name);

	enclave_attesters_opts[registerd_enclave_attester_nums++] = new_opts;

	RTLS_INFO("the enclave attester '%s' registered with type '%s'\n", new_opts->name,
		  new_opts->type);

	return ENCLAVE_ATTESTER_ERR_NONE;

err:
	free(new_opts);
	return -ENCLAVE_ATTESTER_ERR_INVALID;
}
