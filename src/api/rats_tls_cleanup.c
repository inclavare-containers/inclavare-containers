/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <rats-tls/api.h>
#include <rats-tls/log.h>

#include "internal/core.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include "internal/tls_wrapper.h"

rats_tls_err_t rats_tls_cleanup(rats_tls_handle handle)
{
	rtls_core_context_t *ctx = (rtls_core_context_t *)handle;

	RTLS_DEBUG("handle %p\n", ctx);

	if (!handle || !handle->tls_wrapper || !handle->tls_wrapper->opts ||
	    !handle->tls_wrapper->opts->cleanup || !handle->attester || !handle->attester->opts ||
	    !handle->attester->opts->cleanup || !handle->verifier || !handle->verifier->opts ||
	    !handle->verifier->opts->cleanup)
		return -RATS_TLS_ERR_INVALID;

	tls_wrapper_err_t err = handle->tls_wrapper->opts->cleanup(handle->tls_wrapper);
	if (err != TLS_WRAPPER_ERR_NONE) {
		RTLS_DEBUG("failed to clean up tls wrapper %#x\n", err);
		return err;
	}

	enclave_attester_err_t err_ea = handle->attester->opts->cleanup(handle->attester);
	if (err_ea != ENCLAVE_ATTESTER_ERR_NONE) {
		RTLS_DEBUG("failed to clean up attester %#x\n", err_ea);
		return -RATS_TLS_ERR_INVALID;
	}

	enclave_verifier_err_t err_ev = handle->verifier->opts->cleanup(handle->verifier);
	if (err_ev != ENCLAVE_VERIFIER_ERR_NONE) {
		RTLS_DEBUG("failed to clean up verifier %#x\n", err_ev);
		return -RATS_TLS_ERR_INVALID;
	}

	free(ctx);

	return RATS_TLS_ERR_NONE;
}
