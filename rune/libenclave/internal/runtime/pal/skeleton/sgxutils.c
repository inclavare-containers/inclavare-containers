#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include "sgx.h"

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

static bool try_get_xcr0(uint64_t *value)
{
	int cpu_info[4] = {0, 0, 0, 0};

	*value = SGX_XFRM_LEGACY;

	// check if xgetbv instruction is supported
	__cpuid(cpu_info, 1);
	// ecx[27:26] indicate whether support xsave/xrstor, and whether enable xgetbv, xsetbv
	if (!(cpu_info[2] & (1<<XSAVE_SHIFT)) || !(cpu_info[2] & (1<<OSXSAVE_SHIFT)))
		return false;

	*value = get_xcr0();

	// check if xsavec is supported
	// Assume that XSAVEC is always supported if XSAVE is supported
	cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
	__cpuidex(cpu_info, 0xD, 1);
	if (!(cpu_info[0] & (1<<XSAVEC_SHIFT)))
		return false;

	return true;
}

void get_sgx_xfrm_by_cpuid(uint64_t *xfrm)
{
	int cpu_info[4] = {0, 0, 0, 0};

	__cpuidex(cpu_info, SGX_LEAF, 1);

	if (try_get_xcr0(xfrm) == false) {
	// if XSAVE is supported, while XSAVEC is not supported,
	// set xfrm to legacy, because XSAVEC cannot be executed within enclave.
		*xfrm = SGX_XFRM_LEGACY;
	} else {
	// If x-feature is supported and enabled by OS, we need make sure it is also supported in enclave.
		*xfrm &= (((uint64_t)cpu_info[3] << 32) | cpu_info[2]);
	}
}
