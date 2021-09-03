/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <stdlib.h>
#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/core.h"
#include "internal/verifier.h"

#define PATTERN_PREFIX "libverifier_"
#ifdef SGX
#define PATTERN_SUFFIX ".a"
#else
#define PATTERN_SUFFIX ".so"
#endif
// clang-format on

rats_tls_err_t rtls_enclave_verifier_post_init(const char *name, void *handle)
{
	unsigned int i = 0;
	enclave_verifier_opts_t *opts = NULL;
	for (; i < registerd_enclave_verifier_nums; ++i) {
		opts = enclave_verifiers_opts[i];

		if (!strcmp(name, opts->name))
			break;
	}

	if (i == registerd_enclave_verifier_nums) {
		RTLS_DEBUG("the enclave verifier '%s' failed to be registered\n", name);
		return -RATS_TLS_ERR_NOT_REGISTERED;
	}

	if (opts->pre_init) {
		enclave_verifier_err_t err_ev = opts->pre_init();

		if (err_ev != ENCLAVE_VERIFIER_ERR_NONE) {
			RTLS_ERR("failed on pre_init() of enclave verifier '%s' %#x\n", name,
				 err_ev);
			return -RATS_TLS_ERR_INVALID;
		}
	}

	enclave_verifier_ctx_t *verifier_ctx = calloc(1, sizeof(*verifier_ctx));
	if (!verifier_ctx)
		return -RATS_TLS_ERR_NO_MEM;

	verifier_ctx->opts = opts;
	verifier_ctx->log_level = global_core_context.config.log_level;
	verifier_ctx->handle = handle;

	enclave_verifiers_ctx[enclave_verifier_nums++] = verifier_ctx;

	return RATS_TLS_ERR_NONE;
}

rats_tls_err_t rtls_enclave_verifier_load_single(const char *fname)
{
	RTLS_DEBUG("loading the enclave verifier instance '%s' ...\n", fname);

	/* Check whether the filename pattern matches up libenclave_verifier_<name>.so */
	if (strlen(fname) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(fname, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(fname + strlen(fname) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX,
		    strlen(PATTERN_SUFFIX))) {
		RTLS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX
			 "<name>" PATTERN_SUFFIX "\n",
			 fname);
		return -RATS_TLS_ERR_INVALID;
	}

	char realpath[strlen(ENCLAVE_VERIFIERS_DIR) + strlen(fname) + 1];
	snprintf(realpath, sizeof(realpath), "%s%s", ENCLAVE_VERIFIERS_DIR, fname);

	size_t name_len = strlen(fname) - strlen(PATTERN_PREFIX) - strlen(PATTERN_SUFFIX);
	char name[name_len + 1];
	snprintf(name, sizeof(name), "%s", fname + strlen(PATTERN_PREFIX));

	void *handle = NULL;
	rats_tls_err_t err = rtls_instance_init(name, realpath, &handle);
	if (err != RATS_TLS_ERR_NONE)
		return err;

	err = rtls_enclave_verifier_post_init(name, handle);
	if (err != RATS_TLS_ERR_NONE)
		return err;

	RTLS_DEBUG("the enclave verifier '%s' loaded\n", name);

	return RATS_TLS_ERR_NONE;
}
