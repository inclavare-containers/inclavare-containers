/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _UTILS_H
#define _UTILS_H

#include <stdbool.h>
#include "amdcert.h"
#include "sevapi.h"

int sev_load_ask_cert(amd_cert *ask_cert, amd_cert *ark_cert);
bool reverse_bytes(uint8_t *bytes, size_t size);

#endif
