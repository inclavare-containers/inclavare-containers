/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _AMDCERT_H
#define _AMDCERT_H

#include "sevapi.h"
#include "utils.h"

#define AMD_CERT_ID_SIZE_BYTES 16 // sizeof(amd_cert:key_id_0 + amd_cert:key_id_1)
#define AMD_CERT_VERSION       0x01
#define AMD_CERT_KEY_BITS_2K   2048
#define AMD_CERT_KEY_BITS_4K   4096
#define AMD_CERT_KEY_BYTES_4K  512

static uint8_t amd_root_key_id_naples[AMD_CERT_ID_SIZE_BYTES] = { 0x1b, 0xb9, 0x87, 0xc3,
								  0x59, 0x49, 0x46, 0x06,
								  0xb1, 0x74, 0x94, 0x56,
								  0x01, 0xc9, 0xea, 0x5b };

static uint8_t amd_root_key_id_rome[AMD_CERT_ID_SIZE_BYTES] = { 0xe6, 0x00, 0x21, 0x22, 0xfb, 0x58,
								0x41, 0x93, 0x99, 0xd1, 0x5f, 0xee,
								0x7b, 0x13, 0x13, 0x51 };

static uint8_t amd_root_key_id_milan[AMD_CERT_ID_SIZE_BYTES] = { 0x94, 0xC3, 0x8E, 0x41, 0x77, 0xD0,
								 0x47, 0x92, 0x92, 0xA7, 0xAE, 0x67,
								 0x1D, 0x08, 0x3F, 0xB6 };

size_t amd_cert_get_size(const amd_cert *cert);
SEV_ERROR_CODE amd_cert_init(amd_cert *cert, const uint8_t *buffer);
SEV_ERROR_CODE amd_cert_validate_sig(const amd_cert *cert, const amd_cert *parent,
				     enum ePSP_DEVICE_TYPE device_type);
SEV_ERROR_CODE amd_cert_validate_ark(const amd_cert *ark);
SEV_ERROR_CODE amd_cert_validate_ask(const amd_cert *ask, const amd_cert *ark);
SEV_ERROR_CODE amd_cert_export_pub_key(const amd_cert *cert, sev_cert *pub_key_cert);

#endif
