/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <rats-tls/log.h>
#include <rats-tls/attester.h>
#include <stddef.h>
#include "tdx.h"

#define VSOCK true

#ifdef VSOCK
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "tdx_attest.h"
#endif

static int tdx_get_report(const tdx_report_data_t *report_data, tdx_report_t *tdx_report)
{
	/* Get report by tdcall */
	if (tdx_att_get_report(report_data, tdx_report) != TDX_ATTEST_SUCCESS) {
		RTLS_ERR("failed to ioctl get tdx report data.\n");
		return -1;
	}

	return 0;
}

static int tdx_gen_quote(uint8_t *hash, uint8_t *quote_buf, uint32_t *quote_size)
{
	if (hash == NULL) {
                RTLS_ERR("empty hash pointer.\n");
                return -1;
	}

	tdx_report_t tdx_report = {{0}};
	tdx_report_data_t report_data = {{0}};
	assert(sizeof(report_data.d) >= SHA256_HASH_SIZE);
	memcpy(report_data.d, hash, SHA256_HASH_SIZE);
	int ret = tdx_get_report(&report_data, &tdx_report);
	if (ret != 0) {
                RTLS_ERR("failed to get tdx report.\n");
                return -1;
        }

#ifdef VSOCK
	tdx_uuid_t selected_att_key_id = {{0}};
	uint8_t *p_quote = NULL;
	uint32_t p_quote_size = 0;
	if (tdx_att_get_quote(&report_data, NULL, 0,
			      &selected_att_key_id, &p_quote, &p_quote_size, 0) != TDX_ATTEST_SUCCESS) {
		RTLS_ERR("failed to get tdx quote.\n");
		return -1;
	}

	if (p_quote_size > *quote_size) {
		RTLS_ERR("quote buffer is too small.\n");
		tdx_att_free_quote(p_quote);
		return -1;
	}

	memcpy(quote_buf, p_quote, p_quote_size);
	*quote_size = p_quote_size;
	tdx_att_free_quote(p_quote);
#else
	/* This branch is for getting quote size and quote by tdcall,
	 * it depends on the implemetation in qemu.
	 */
	#error "using tdcall to retrieve TD quote is still not supported!"
#endif

	return 0;
}

enclave_attester_err_t tdx_collect_evidence(enclave_attester_ctx_t *ctx,
                                            attestation_evidence_t *evidence,
                                            rats_tls_cert_algo_t algo, uint8_t *hash)
{
	RTLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	evidence->tdx.quote_len = sizeof(evidence->tdx.quote);
	if (tdx_gen_quote(hash, evidence->tdx.quote, &evidence->tdx.quote_len)) {
		RTLS_ERR("failed to generate quote\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	RTLS_DEBUG("Succeed to generate the quote!\n");

	/* Essentially speaking, QGS generates the same
	 * format of quote as sgx_ecdsa.
	 */
	snprintf(evidence->type, sizeof(evidence->type), "%s", "tdx_ecdsa");

	RTLS_DEBUG("ctx %p, evidence %p, quote_size %d\n", ctx, evidence, evidence->tdx.quote_len);

	return ENCLAVE_ATTESTER_ERR_NONE;
}
