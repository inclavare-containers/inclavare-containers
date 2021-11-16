/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _TDX_ECDSA_H
#define _TDX_ECDSA_H

#include <rats-tls/api.h>

#define TDX_NUM_RTMRS 4

typedef struct {
	uint8_t mrowner[SHA384_HASH_SIZE];
} tdx_ctx_t;

/* TDX attestation specification */

typedef struct {
	uint16_t version;
	uint16_t attestation_key_type;
	uint32_t tee_type;
	uint16_t qe_svn;
	uint16_t pce_svn;
	uint8_t qe_vendor_id[16];
	uint8_t user_data[20];
} __attribute__((packed)) tdx_quote_header_t;

typedef struct {
	uint8_t tee_tcb_svn[16];
	uint8_t mrseam[SHA384_HASH_SIZE];
	uint8_t mrsigner_seam[SHA384_HASH_SIZE];
	uint8_t seam_attributes[8];
	uint8_t td_attributes[8];
	uint8_t xfam[8];
	uint8_t mrtd[SHA384_HASH_SIZE];
	uint8_t mrconfig_id[SHA384_HASH_SIZE];
	uint8_t mrowner[SHA384_HASH_SIZE];
	uint8_t mrowner_config[SHA384_HASH_SIZE];
	uint8_t rtmr[TDX_NUM_RTMRS][SHA384_HASH_SIZE];
	uint8_t report_data[64];
} __attribute__((packed)) tdx_report_body_t;

/* FIXME: currently we only care about report data */
typedef struct {
	tdx_quote_header_t header;
	tdx_report_body_t report_body;
} __attribute__((__packed__)) tdx_quote_t;

#endif	/* _TDX_ECDSA_H */
