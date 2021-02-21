/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) WITH Linux-syscall-note */
/*
 * Copyright(c) 2016-19 Intel Corporation.
 */
/* *INDENT-OFF* */
#ifndef _UAPI_ASM_X86_SGX_H
#define _UAPI_ASM_X86_SGX_H
/* *INDENT-ON* */

#include <linux/types.h>
#include <linux/ioctl.h>
#include <stdbool.h>

/**
 * enum sgx_epage_flags - page control flags
 * %SGX_PAGE_MEASURE:	Measure the page contents with a
 * sequence of ENCLS[EEXTEND] operations.
 */
enum sgx_page_flags {
	SGX_PAGE_MEASURE = 0x01,
};

#define	SGX_LEAF	0x12

// CPUID leafs
#define	CPUIID_EXTENDED_FEATURE_FLAGS	0x7

/**
 *CPUID function 1
 *ECX[26] enums general support for XSAVE
 *ECX[27] enums XSAVE is enabled or not
*/
#define	XSAVE_SHIFT	26
#define	OSXSAVE_SHIFT	27

/**
 *CPUID function 0DH, sub-function 1
 *EAX[1] enums support for compaction extensions to XSAVE
 */
#define	XSAVEC_SHIFT	1

/* XSAVE Feature Request Mask */
#define	SGX_XFRM_LEGACY	0x0000000000000003ULL
						/* Legacy XFRM which includes the basic feature bits required by SGX, x87 state(0x01) and SSE state(0x02) */

#define SGX_MAGIC 0xA4

#define SGX_IOC_ENCLAVE_CREATE \
	_IOW(SGX_MAGIC, 0x00, struct sgx_enclave_create)
#define SGX_IOC_ENCLAVE_ADD_PAGES \
	_IOWR(SGX_MAGIC, 0x01, struct sgx_enclave_add_pages)
#define SGX_IOC_ENCLAVE_ADD_PAGES_WITH_MRMASK \
	_IOW(SGX_MAGIC, 0x01, struct sgx_enclave_add_pages_with_mrmask)
#define SGX_IOC_ENCLAVE_INIT \
	_IOW(SGX_MAGIC, 0x02, struct sgx_enclave_init)
#define SGX_IOC_ENCLAVE_INIT_WITH_TOKEN \
	_IOW(SGX_MAGIC, 0x02, struct sgx_enclave_init_with_token)
#define SGX_IOC_ENCLAVE_SET_ATTRIBUTE \
	_IOW(SGX_MAGIC, 0x03, struct sgx_enclave_set_attribute)

/**
 * struct sgx_enclave_create - parameter structure for the
 *                             %SGX_IOC_ENCLAVE_CREATE ioctl
 * @src:	address for the SECS page data
 */
struct sgx_enclave_create {
	__u64 src;
};

/**
 * struct sgx_enclave_add_pages - parameter structure for the
 *                                %SGX_IOC_ENCLAVE_ADD_PAGE ioctl
 * @src:	start address for the page data (must be 4k aligned required by kernel)
 * @offset:	starting page offset
 * @length:	length of the data (multiple of the page size)
 * @secinfo:	address for the SECINFO data
 * @flags:	page control flags
 * @count:	number of bytes added (multiple of the page size)
 */
struct sgx_enclave_add_pages {
	__u64 src;
	__u64 offset;
	__u64 length;
	__u64 secinfo;
	__u64 flags;
	__u64 count;
};

/**
 * struct sgx_enclave_add_pages_with_mrmask - parameter structure for the
 *                               %SGX_IOC_ENCLAVE_ADD_PAGE_WITH_MRMASK ioctl
 * @addr:       address in the ELRANGE
 * @src:        address for the page data
 * @secinfo:    address for the SECINFO data
 * @mrmask:     bitmask for the 256 byte chunks that are to be measured
 */
struct sgx_enclave_add_pages_with_mrmask {
	__u64 addr;
	__u64 src;
	__u64 secinfo;
	__u16 mrmask;
} __attribute__((__packed__));

/**
 * struct sgx_enclave_init - parameter structure for the
 *                           %SGX_IOC_ENCLAVE_INIT ioctl
 * @sigstruct:	address for the SIGSTRUCT data
 */
struct sgx_enclave_init {
	__u64 sigstruct;
};

/**
 * struct sgx_enclave_init - parameter structure for the
 *                           %SGX_IOC_ENCLAVE_INIT_WITH_TOKEN ioctl
 * @addr:       address in the ELRANGE
 * @sigstruct:  address for the page data
 * @einittoken: EINITTOKEN
 */
struct sgx_enclave_init_with_token {
	__u64 addr;
	__u64 sigstruct;
	__u64 einittoken;
} __attribute__((__packed__));

/**
 * struct sgx_enclave_set_attribute - parameter structure for the
 *				      %SGX_IOC_ENCLAVE_SET_ATTRIBUTE ioctl
 * @attribute_fd:	file handle of the attribute file in the securityfs
 */
struct sgx_enclave_set_attribute {
	__u64 attribute_fd;
};

/**
 * struct sgx_enclave_exception - structure to report exceptions encountered in
 *				  __vdso_sgx_enter_enclave()
 *
 * @leaf:	ENCLU leaf from \%eax at time of exception
 * @trapnr:	exception trap number, a.k.a. fault vector
 * @error_code:	exception error code
 * @address:	exception address, e.g. CR2 on a #PF
 * @reserved:	reserved for future use
 */
struct sgx_enclave_exception {
	__u32 leaf;
	__u16 trapnr;
	__u16 error_code;
	__u64 address;
	__u64 reserved[2];
};

/**
 * typedef sgx_enclave_exit_handler_t - Exit handler function accepted by
 *					__vdso_sgx_enter_enclave()
 *
 * @rdi:	RDI at the time of enclave exit
 * @rsi:	RSI at the time of enclave exit
 * @rdx:	RDX at the time of enclave exit
 * @ursp:	RSP at the time of enclave exit (untrusted stack)
 * @r8:		R8 at the time of enclave exit
 * @r9:		R9 at the time of enclave exit
 * @tcs:	Thread Control Structure used to enter enclave
 * @ret:	0 on success (EEXIT), -EFAULT on an exception
 * @e:		Pointer to struct sgx_enclave_exception (as provided by caller)
 */
/* *INDENT-OFF* */
typedef int (*sgx_enclave_exit_handler_t)(long rdi, long rsi, long rdx,
					  long ursp, long r8, long r9,
					  void *tcs, int ret,
					  struct sgx_enclave_exception *e);

void get_sgx_xfrm_by_cpuid(uint64_t *xfrm);
/* *INDENT-ON* */
uint32_t sgx_calc_ssaframesize(uint32_t miscselect, uint64_t xfrm);
uint32_t get_sgx_miscselect_by_cpuid(void);
bool is_launch_control_supported(void);
bool is_sgx1_supported(void);
bool is_sgx2_supported(void);
uint32_t get_build_date(void);

/* *INDENT-OFF* */
#endif   /* _UAPI_ASM_X86_SGX_H */
/* *INDENT-ON* */
