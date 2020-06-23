/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(c) 2016-19 Intel Corporation.
 */

#ifndef DEFINES_H
#define DEFINES_H

#include <stdint.h>

#define __aligned(x) __attribute__((__aligned__(x)))
#define __packed __attribute__((packed))
#define static_assert _Static_assert

#include "arch.h"
#include "sgx.h"

#endif /* DEFINES_H */
