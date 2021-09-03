/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RTLS_SYSCALL_H_
#define _RTLS_SYSCALL_H_

#include <sys/types.h>

struct ocall_dirent {
	u_int64_t d_ino;
	int64_t d_off; //off_t
	u_int16_t d_reclen;
	u_int8_t d_type;
	char d_name[256]; // NAME_MAX + 1 = 256
};

typedef u_int64_t uint64_t;

#endif
