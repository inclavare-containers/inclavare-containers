/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _PER_THREAD_H
#define _PER_THREAD_H

#include <pthread.h>

extern void per_thread_key_init(void);
extern int per_thread_setspecific(void *value);
extern void *per_thread_getspecific(void);

#endif
