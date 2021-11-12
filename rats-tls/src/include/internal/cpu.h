/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>

#define SGX_CPUID 0x12
#define TDX_CPUID 0x21

#define SGX1_STRING     0x00000001
#define SGX2_STRING     0x00000002
#define TDX_STRING_HIGH 0x65746e49
#define TDX_STRING_LOW  0x5844546c

extern bool is_sgx1_supported(void);
extern bool is_sgx2_supported(void);
extern bool is_in_tdguest(void);
