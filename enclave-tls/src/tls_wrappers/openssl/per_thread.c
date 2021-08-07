/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include "per_thread.h"
#include <pthread.h>

static pthread_key_t g_key;
static pthread_once_t g_key_once = PTHREAD_ONCE_INIT;

void per_thread_key_destroy(void *data)
{
	free(data);
}

void per_thread_key_alloc(void)
{
	pthread_key_create(&g_key, per_thread_key_destroy);
}

void per_thread_key_init(void)
{
	pthread_once(&g_key_once, per_thread_key_alloc);
}

int per_thread_setspecific(void *value)
{
	if (!pthread_setspecific(g_key, value))
		return 1;

	/* return 0 indicates failure */
	return 0;
}

void *per_thread_getspecific(void)
{
	return pthread_getspecific(g_key);
}
