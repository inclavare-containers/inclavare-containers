#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/user.h>
#include "sgx.h"
#include "defines.h"

static inline void cpuid(int *eax, int *ebx, int *ecx, int *edx)
{
#if defined(__x86_64__)
	asm volatile ("cpuid"
		      : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
		      : "0" (*eax), "2" (*ecx)
		      : "memory");
#else
	/* on 32bit, ebx can NOT be used as PIC code */
	asm volatile ("xchgl %%ebx, %1; cpuid; xchgl %%ebx, %1"
		      : "=a" (*eax), "=r" (*ebx), "=c" (*ecx), "=d" (*edx)
		      : "0" (*eax), "2" (*ecx)
		      : "memory");
#endif
}

static inline void __cpuid(int a[4], int b)
{
	a[0] = b;
	a[2] = 0;
	cpuid(&a[0], &a[1], &a[2], &a[3]);
}

static inline void __cpuidex(int a[4], int b, int c)
{
	a[0] = b;
	a[2] = c;
	cpuid(&a[0], &a[1], &a[2], &a[3]);
}

static inline uint64_t xgetbv(uint32_t index)
{
	uint32_t eax, edx;

	asm volatile(".byte 0x0f,0x01,0xd0" /* xgetbv */
		     : "=a" (eax), "=d" (edx)
		     : "c" (index));

	return eax + ((uint64_t)edx << 32);
}

static inline uint64_t get_xcr0()
{
	return xgetbv(0);
}

static uint64_t try_get_xcr0()
{
	int cpu_info[4] = {0, 0, 0, 0};

	// Check if xgetbv instruction is supported.
	__cpuid(cpu_info, 1);
	// ecx[27:26] indicate whether support xsave/xrstor, and whether enable xgetbv, xsetbv.
	if (!(cpu_info[2] & (1 << OSXSAVE_SHIFT)))
		return SGX_XFRM_LEGACY;

	// If XSAVE is supported, while XSAVEC is not supported,
	// set xfrm to legacy, because skeleton requires XSAVEC feature available on the path of enclave-exit.
	__cpuidex(cpu_info, 0xD, 1);
	if (!(cpu_info[0] & (1 << XSAVEC_SHIFT)))
		return SGX_XFRM_LEGACY;

	// If x-feature is supported and enabled by OS, we need make sure it is also supported in enclave.
	__cpuidex(cpu_info, SGX_LEAF, 1);
	return (get_xcr0() & (((uint64_t)cpu_info[3] << 32) | cpu_info[2]));
}

void get_sgx_xfrm_by_cpuid(uint64_t *xfrm)
{
	*xfrm = try_get_xcr0();
}

uint32_t sgx_calc_ssaframesize(uint32_t miscselect, uint64_t xfrm)
{
	uint32_t xsave_offset;
	uint32_t size_max = PAGE_SIZE;
	int cpu_info[4] = {0, 0, 0, 0};
	uint32_t size;
	int i;

	for (i = 2; i < 63; i++) {
		__cpuidex(cpu_info, 0x0D, i);
		if (!((1 << i) & xfrm))
			continue;
		xsave_offset = cpu_info[0] + cpu_info[1];

		size = SGX_SSA_GPRS_SIZE + xsave_offset;
		if (miscselect & SGX_MISC_EXINFO)
			size += SGX_SSA_MISC_EXINFO_SIZE;

		if (size > size_max)
			size_max = size;
	}

	return (size_max + PAGE_SIZE - 1) >> PAGE_SHIFT;
}

uint32_t get_sgx_miscselect_by_cpuid(void)
{
	int cpu_info[4] = {0, 0, 0, 0};

	__cpuidex(cpu_info, SGX_CPUID, 0);

	return cpu_info[1];
}

bool is_launch_control_supported(void)
{
	int cpu_info[4] = {0, 0, 0, 0};

	__cpuidex(cpu_info, CPUIID_EXTENDED_FEATURE_FLAGS, 0);

	return !!(cpu_info[2] & 0x40000000);
}
