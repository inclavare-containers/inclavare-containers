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
// clang-format off
#ifndef SGX
#include <sys/stat.h>
#include <sys/sysmacros.h>
#else
#include "rtls_t.h"
#endif
// clang-format on

#ifndef SGX
// clang-format off
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
// clang-format on

static inline void __cpuidex(int a[4], int b, int c)
{
	a[0] = b;
	a[2] = c;
	cpuid(&a[0], &a[1], &a[2], &a[3]);
}

static bool is_sgx_device(const char *dev)
{
	struct stat st;

	if (!stat(dev, &st)) {
		if ((st.st_mode & S_IFCHR) && (major(st.st_rdev) == SGX_DEVICE_MAJOR_NUM))
			return true;
	}

	return false;
}

static bool is_legacy_oot_kernel_driver(void)
{
	return is_sgx_device("/dev/isgx");
}

/* Prior to DCAP 1.10 release, the DCAP OOT driver uses this legacy
 * name.
 */
static bool is_dcap_1_9_oot_kernel_driver(void)
{
	return is_sgx_device("/dev/sgx/enclave");
}

/* Since DCAP 1.10 release, the DCAP OOT driver uses the same name
 * as in-tree driver.
 */
static bool is_in_tree_kernel_driver(void)
{
	return is_sgx_device("/dev/sgx_enclave");
}
#else
static inline void __cpuidex(int a[4], int b, int c)
{
	a[0] = b;
	a[2] = c;
	ocall_cpuid(&a[0], &a[1], &a[2], &a[3]);
}

static bool is_legacy_oot_kernel_driver(void)
{
	bool retval;

	ocall_is_sgx_dev(&retval, "/dev/isgx");

	return retval;
}

/* Prior to DCAP 1.10 release, the DCAP OOT driver uses this legacy
 * name.
 */
static bool is_dcap_1_9_oot_kernel_driver(void)
{
	bool retval;

	ocall_is_sgx_dev(&retval, "/dev/sgx/enclave");

	return retval;
}

/* Since DCAP 1.10 release, the DCAP OOT driver uses the same name
 * as in-tree driver.
 */
static bool is_in_tree_kernel_driver(void)
{
	bool retval;

	ocall_is_sgx_dev(&retval, "/dev/sgx_enclave");

	return retval;
}
#endif

/* return true means in sgx1 enabled */
static bool __is_sgx1_supported(void)
{
	int cpu_info[4] = { 0, 0, 0, 0 };

	__cpuidex(cpu_info, SGX_CPUID, 0);

	return !!(cpu_info[0] & SGX1_STRING);
}

static bool __is_sgx2_supported(void)
{
	int cpu_info[4] = { 0, 0, 0, 0 };

	__cpuidex(cpu_info, SGX_CPUID, 0);

	return !!(cpu_info[0] & SGX2_STRING);
}

bool is_sgx1_supported(void)
{
	if (!__is_sgx1_supported())
		return false;

	/* SGX2 using ECDSA attestation is not compatible with SGX1
         * which uses EPID attestation.
         */
	if (is_sgx2_supported())
		return false;

	/* Check whether the kernel driver is accessible */
	if (!is_legacy_oot_kernel_driver())
		return false;

	return true;
}

bool is_sgx2_supported(void)
{
	if (!__is_sgx2_supported())
		return false;

	/* Check whether the kernel driver is accessible */
	if (!is_dcap_1_9_oot_kernel_driver() && !is_in_tree_kernel_driver())
		return false;

	return true;
}

/* return true means in td guest */
bool is_tdguest_supported(void)
{
	uint32_t sig[4] = { 0, 0, 0, 0 };

	__cpuidex(sig, TDX_CPUID, 0);

	/* "IntelTDX    " */
	return (sig[1] == 0x65746e49) && (sig[3] == 0x5844546c) && (sig[2] == 0x20202020);
}
