/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal/cpu.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

static inline void cpuid(int *eax, int *ebx, int *ecx, int *edx)
{
#if defined(__x86_64__)
    asm volatile("cpuid"
                 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                 : "0"(*eax), "1"(*ebx), "2"(*ecx), "3"(*edx)
                 : "memory");
#else
    /* on 32bit, ebx can NOT be used as PIC code */
    asm volatile("xchgl %%ebx, %1; cpuid; xchgl %%ebx, %1"
                 : "=a"(*eax), "=r"(*ebx), "=c"(*ecx), "=d"(*edx)
                 : "0"(*eax), "1"(*ebx), "2"(*ecx), "3"(*edx)
                 : "memory");
#endif
}

static inline void __cpuidex(int a[4], int b, int c)
{
    a[0] = b;
    a[2] = c;
    cpuid(&a[0], &a[1], &a[2], &a[3]);
}

/* return true means in sgx1 enabled */
bool is_sgx1_supported(void)
{
    int cpu_info[4] = {0, 0, 0, 0};

    __cpuidex(cpu_info, SGX_CPUID, 0);

    return !!(cpu_info[0] & SGX1_STRING);
}

/* return true means in sgx2 enabled */
bool is_sgx2_supported(void)
{
    int cpu_info[4] = {0, 0, 0, 0};

    __cpuidex(cpu_info, SGX_CPUID, 0);

    return !!(cpu_info[0] & SGX2_STRING);
}

/* return true means in td guest */
bool is_in_tdguest(void)
{
    int cpu_info[4] = {0, 0, 0, 0};

    __cpuidex(cpu_info, TDX_CPUID, 0);

    return !((cpu_info[1] & (!(TDX_STRING_HIGH))) &&
             (cpu_info[3] & (!(TDX_STRING_LOW))));
}
