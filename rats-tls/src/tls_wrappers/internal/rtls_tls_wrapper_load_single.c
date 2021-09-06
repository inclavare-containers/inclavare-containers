/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <rats-tls/err.h>
#include <rats-tls/log.h>
#include "internal/core.h"
#include "internal/tls_wrapper.h"

// clang-format off
#define PATTERN_PREFIX "libtls_wrapper_"
#ifdef SGX
#define PATTERN_SUFFIX ".a"
#else
#define PATTERN_SUFFIX ".so"
#endif
// clang-format on

rats_tls_err_t rtls_rats_tls_post_init(const char *name, void *handle)
{
	unsigned int i = 0;
	tls_wrapper_opts_t *opts = NULL;
	for (i = 0; i < registerd_tls_wrapper_nums; ++i) {
		opts = tls_wrappers_opts[i];

		if (!strcmp(name, opts->name))
			break;
	}

	if (i == registerd_tls_wrapper_nums) {
		RTLS_DEBUG("the tls wrapper '%s' failed to registered\n", name);
		return -RATS_TLS_ERR_NOT_REGISTERED;
	}

	if (opts->pre_init) {
		tls_wrapper_err_t err_tw = opts->pre_init();

		if (err_tw != TLS_WRAPPER_ERR_NONE) {
			RTLS_ERR("failed on pre_init() of tls wrapper '%s' %#x\n", name, err_tw);
			return err_tw;
		}
	}

	tls_wrapper_ctx_t *tls_ctx = calloc(1, sizeof(*tls_ctx));
	if (!tls_ctx)
		return -RATS_TLS_ERR_NO_MEM;

	tls_ctx->opts = opts;
	tls_ctx->fd = -1;
	tls_ctx->conf_flags = global_core_context.config.flags;
	tls_ctx->log_level = global_core_context.config.log_level;
	tls_ctx->handle = handle;

	tls_wrappers_ctx[tls_wrappers_nums++] = tls_ctx;

	return RATS_TLS_ERR_NONE;
}

rats_tls_err_t rtls_tls_wrapper_load_single(const char *fname)
{
	RTLS_DEBUG("loading the tls wrapper instance '%s' ...\n", fname);

	/* Check whether the filename pattern matches up libtls_wrapper_<name>.so */
	if (strlen(fname) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(fname, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(fname + strlen(fname) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX,
		    strlen(PATTERN_SUFFIX))) {
		RTLS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX
			 "<name>" PATTERN_SUFFIX "\n",
			 fname);
		return -RATS_TLS_ERR_INVALID;
	}

	char realpath[strlen(TLS_WRAPPERS_DIR) + strlen(fname) + 1];
	snprintf(realpath, sizeof(realpath), "%s%s", TLS_WRAPPERS_DIR, fname);

	size_t name_len = strlen(fname) - strlen(PATTERN_PREFIX) - strlen(PATTERN_SUFFIX);
	char name[name_len + 1];
	snprintf(name, sizeof(name), "%s", fname + strlen(PATTERN_PREFIX));

	void *handle = NULL;
	rats_tls_err_t err = rtls_instance_init(name, realpath, &handle);
	if (err != RATS_TLS_ERR_NONE)
		return err;

	err = rtls_rats_tls_post_init(name, handle);
	if (err != RATS_TLS_ERR_NONE)
		return err;

	RTLS_DEBUG("the tls wrapper '%s' loaded\n", name);

	return RATS_TLS_ERR_NONE;
}
