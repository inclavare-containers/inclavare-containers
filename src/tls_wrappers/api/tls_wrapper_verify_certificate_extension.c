/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <rats-tls/log.h>
#include <rats-tls/err.h>

#include "internal/tls_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"

tls_wrapper_err_t tls_wrapper_verify_certificate_extension(tls_wrapper_ctx_t *tls_ctx,
							   attestation_evidence_t *evidence,
							   uint8_t *hash, uint32_t hash_len)
{
	RTLS_DEBUG("tls_wrapper_verify_certificate_extension() called with evidence type: '%s'\n",
		   evidence->type);

	if (!tls_ctx || !tls_ctx->rtls_handle || !tls_ctx->rtls_handle->verifier ||
	    !tls_ctx->rtls_handle->verifier->opts ||
	    !tls_ctx->rtls_handle->verifier->opts->verify_evidence)
		return -TLS_WRAPPER_ERR_INVALID;

	if (strcmp(tls_ctx->rtls_handle->verifier->opts->type, evidence->type) &&
	    !(tls_ctx->rtls_handle->flags & RATS_TLS_CONF_VERIFIER_ENFORCED)) {
		RTLS_WARN("type doesn't match between verifier '%s' and evidence '%s'\n",
			  tls_ctx->rtls_handle->verifier->opts->name, evidence->type);
		rats_tls_err_t tlserr =
			rtls_verifier_select(tls_ctx->rtls_handle, evidence->type,
					     tls_ctx->rtls_handle->config.cert_algo);
		if (tlserr != RATS_TLS_ERR_NONE) {
			RTLS_ERR("the verifier selecting err %#x during verifying cert extension\n",
				 tlserr);
			return -TLS_WRAPPER_ERR_INVALID;
		}
	}

	enclave_verifier_err_t err = tls_ctx->rtls_handle->verifier->opts->verify_evidence(
		tls_ctx->rtls_handle->verifier, evidence, hash, hash_len);
	if (err != ENCLAVE_VERIFIER_ERR_NONE) {
		RTLS_ERR("failed to verify evidence %#x\n", err);
		return -TLS_WRAPPER_ERR_INVALID;
	}

	return TLS_WRAPPER_ERR_NONE;
}
