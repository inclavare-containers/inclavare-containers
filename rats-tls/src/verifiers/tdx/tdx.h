/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _TDX_H
#define _TDX_H

#define MROWNER_SIZE 48

typedef struct {
	uint8_t mrowner[MROWNER_SIZE];
} tdx_ctx_t;

#endif
