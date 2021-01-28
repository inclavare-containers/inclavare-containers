/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
 * Copyright(c) 2016-18 Intel Corporation.
 *
 * Contains data structures defined by the SGX architecture.  Data structures
 * defined by the Linux software stack should not be placed here.
 */
/* *INDENT-OFF* */
#ifndef _ASM_X86_SGX_ARCH_H
#define _ASM_X86_SGX_ARCH_H
/* *INDENT-ON* */

#include <assert.h>
#include <linux/types.h>

#define SGX_CPUID				0x12
#define SGX_CPUID_FIRST_VARIABLE_SUB_LEAF	2

#ifndef BIT
#  define BIT(nr)			(1UL << (nr))
#endif

#define EREPORT			0

/**
 * enum sgx_return_code - The return code type for ENCLS, ENCLU and ENCLV
 * %SGX_NOT_TRACKED:		Previous ETRACK's shootdown sequence has not
 *				been completed yet.
 * %SGX_INVALID_EINITTOKEN:	EINITTOKEN is invalid and enclave signer's
 *				public key does not match IA32_SGXLEPUBKEYHASH.
 * %SGX_UNMASKED_EVENT:		An unmasked event, e.g. INTR, was received
 */
enum sgx_return_code {
	SGX_NOT_TRACKED = 11,
	SGX_INVALID_EINITTOKEN = 16,
	SGX_UNMASKED_EVENT = 128,
};

/**
 * enum sgx_sub_leaf_types - SGX CPUID variable sub-leaf types
 * %SGX_CPUID_SUB_LEAF_INVALID:		Indicates this sub-leaf is invalid.
 * %SGX_CPUID_SUB_LEAF_EPC_SECTION:	Sub-leaf enumerates an EPC section.
 */
enum sgx_sub_leaf_types {
	SGX_CPUID_SUB_LEAF_INVALID = 0x0,
	SGX_CPUID_SUB_LEAF_EPC_SECTION = 0x1,
};

#define SGX_CPUID_SUB_LEAF_TYPE_MASK	GENMASK(3, 0)

#define SGX_MODULUS_SIZE 384
#define SGX_EXPONENT_SIZE 1

/**
 * enum sgx_miscselect - additional information to an SSA frame
 * %SGX_MISC_EXINFO:	Report #PF or #GP to the SSA frame.
 *
 * Save State Area (SSA) is a stack inside the enclave used to store processor
 * state when an exception or interrupt occurs. This enum defines additional
 * information stored to an SSA frame.
 */
enum sgx_miscselect {
	SGX_MISC_EXINFO = BIT(0),
};

#define SGX_MISC_RESERVED_MASK	GENMASK_ULL(63, 1)

#define SGX_SSA_GPRS_SIZE		184
#define SGX_SSA_MISC_EXINFO_SIZE	16

/**
 * enum sgx_attributes - the attributes field in &struct sgx_secs
 * %SGX_ATTR_INIT:		Enclave can be entered (is initialized).
 * %SGX_ATTR_DEBUG:		Allow ENCLS(EDBGRD) and ENCLS(EDBGWR).
 * %SGX_ATTR_MODE64BIT:		Tell that this a 64-bit enclave.
 * %SGX_ATTR_PROVISIONKEY:      Allow to use provisioning keys for remote
 *				attestation.
 * %SGX_ATTR_KSS:		Allow to use key separation and sharing (KSS).
 * %SGX_ATTR_EINITTOKENKEY:	Allow to use token signing key that is used to
 *				sign cryptographic tokens that can be passed to
 *				EINIT as an authorization to run an enclave.
 */
enum sgx_attribute {
	SGX_ATTR_INIT = BIT(0),
	SGX_ATTR_DEBUG = BIT(1),
	SGX_ATTR_MODE64BIT = BIT(2),
	SGX_ATTR_PROVISIONKEY = BIT(4),
	SGX_ATTR_EINITTOKENKEY = BIT(5),
	SGX_ATTR_KSS = BIT(7),
};

#define SGX_ATTR_RESERVED_MASK	(BIT_ULL(3) | BIT_ULL(6) | GENMASK_ULL(63, 8))
#define SGX_ATTR_ALLOWED_MASK	(SGX_ATTR_DEBUG | SGX_ATTR_MODE64BIT | \
				 SGX_ATTR_PROVISIONKEY | SGX_ATTR_EINITTOKENKEY | \
				 SGX_ATTR_KSS)

/**
 * struct sgx_secs - SGX Enclave Control Structure (SECS)
 * @size:		size of the address space
 * @base:		base address of the  address space
 * @ssa_frame_size:	size of an SSA frame
 * @miscselect:		additional information stored to an SSA frame
 * @attributes:		attributes for enclave
 * @xfrm:		XSave-Feature Request Mask (subset of XCR0)
 * @mrenclave:		SHA256-hash of the enclave contents
 * @mrsigner:		SHA256-hash of the public key used to sign the SIGSTRUCT
 * @config_id:		a user-defined value that is used in key derivation
 * @isv_prod_id:	a user-defined value that is used in key derivation
 * @isv_svn:		a user-defined value that is used in key derivation
 * @config_svn:		a user-defined value that is used in key derivation
 *
 * SGX Enclave Control Structure (SECS) is a special enclave page that is not
 * visible in the address space. In fact, this structure defines the address
 * range and other global attributes for the enclave and it is the first EPC
 * page created for any enclave. It is moved from a temporary buffer to an EPC
 * by the means of ENCLS(ECREATE) leaf.
 */
struct sgx_secs {
	uint64_t size;
	uint64_t base;
	uint32_t ssa_frame_size;
	uint32_t miscselect;
	uint8_t reserved1[24];
	uint64_t attributes;
	uint64_t xfrm;
	uint32_t mrenclave[8];
	uint8_t reserved2[32];
	uint32_t mrsigner[8];
	uint8_t reserved3[32];
	uint32_t config_id[16];
	uint16_t isv_prod_id;
	uint16_t isv_svn;
	uint16_t config_svn;
	uint8_t reserved4[3834];
} __packed;

/**
 * enum sgx_tcs_flags - execution flags for TCS
 * %SGX_TCS_DBGOPTIN:	If enabled allows single-stepping and breakpoints
 *			inside an enclave. It is cleared by EADD but can
 *			be set later with EDBGWR.
 */
enum sgx_tcs_flags {
	SGX_TCS_DBGOPTIN = 0x01,
};

#define SGX_TCS_RESERVED_MASK	GENMASK_ULL(63, 1)
#define SGX_TCS_RESERVED_SIZE	4024

/**
 * struct sgx_tcs - Thread Control Structure (TCS)
 * @state:		used to mark an entered TCS
 * @flags:		execution flags (cleared by EADD)
 * @ssa_offset:		SSA stack offset relative to the enclave base
 * @ssa_index:		the current SSA frame index (cleard by EADD)
 * @nr_ssa_frames:	the number of frame in the SSA stack
 * @entry_offset:	entry point offset relative to the enclave base
 * @exit_addr:		address outside the enclave to exit on an exception or
 *			interrupt
 * @fs_offset:		offset relative to the enclave base to become FS
 *			segment inside the enclave
 * @gs_offset:		offset relative to the enclave base to become GS
 *			segment inside the enclave
 * @fs_limit:		size to become a new FS-limit (only 32-bit enclaves)
 * @gs_limit:		size to become a new GS-limit (only 32-bit enclaves)
 *
 * Thread Control Structure (TCS) is an enclave page visible in its address
 * space that defines an entry point inside the enclave. A thread enters inside
 * an enclave by supplying address of TCS to ENCLU(EENTER). A TCS can be entered
 * by only one thread at a time.
 */
struct sgx_tcs {
	uint64_t state;
	uint64_t flags;
	uint64_t ssa_offset;
	uint32_t ssa_index;
	uint32_t nr_ssa_frames;
	uint64_t entry_offset;
	uint64_t exit_addr;
	uint64_t fs_offset;
	uint64_t gs_offset;
	uint32_t fs_limit;
	uint32_t gs_limit;
	uint8_t reserved[SGX_TCS_RESERVED_SIZE];
} __packed;

/**
 * struct sgx_pageinfo - an enclave page descriptor
 * @addr:	address of the enclave page
 * @contents:	pointer to the page contents
 * @metadata:	pointer either to a SECINFO or PCMD instance
 * @secs:	address of the SECS page
 */
struct sgx_pageinfo {
	uint64_t addr;
	uint64_t contents;
	uint64_t metadata;
	uint64_t secs;
} __packed __aligned(32);

/**
 * enum sgx_page_type - bits in the SECINFO flags defining the page type
 * %SGX_PAGE_TYPE_SECS:	a SECS page
 * %SGX_PAGE_TYPE_TCS:	a TCS page
 * %SGX_PAGE_TYPE_REG:	a regular page
 * %SGX_PAGE_TYPE_VA:	a VA page
 * %SGX_PAGE_TYPE_TRIM:	a page in trimmed state
 */
enum sgx_page_type {
	SGX_PAGE_TYPE_SECS,
	SGX_PAGE_TYPE_TCS,
	SGX_PAGE_TYPE_REG,
	SGX_PAGE_TYPE_VA,
	SGX_PAGE_TYPE_TRIM,
};

#define SGX_NR_PAGE_TYPES	5
#define SGX_PAGE_TYPE_MASK	GENMASK(7, 0)

/**
 * enum sgx_secinfo_flags - the flags field in &struct sgx_secinfo
 * %SGX_SECINFO_R:	allow read
 * %SGX_SECINFO_W:	allow write
 * %SGX_SECINFO_X:	allow execution
 * %SGX_SECINFO_SECS:	a SECS page
 * %SGX_SECINFO_TCS:	a TCS page
 * %SGX_SECINFO_REG:	a regular page
 * %SGX_SECINFO_VA:	a VA page
 * %SGX_SECINFO_TRIM:	a page in trimmed state
 */
enum sgx_secinfo_flags {
	SGX_SECINFO_R = BIT(0),
	SGX_SECINFO_W = BIT(1),
	SGX_SECINFO_X = BIT(2),
	SGX_SECINFO_SECS = (SGX_PAGE_TYPE_SECS << 8),
	SGX_SECINFO_TCS = (SGX_PAGE_TYPE_TCS << 8),
	SGX_SECINFO_REG = (SGX_PAGE_TYPE_REG << 8),
	SGX_SECINFO_VA = (SGX_PAGE_TYPE_VA << 8),
	SGX_SECINFO_TRIM = (SGX_PAGE_TYPE_TRIM << 8),
};

#define SGX_SECINFO_PERMISSION_MASK	GENMASK_ULL(2, 0)
#define SGX_SECINFO_PAGE_TYPE_MASK	(SGX_PAGE_TYPE_MASK << 8)
#define SGX_SECINFO_RESERVED_MASK	~(SGX_SECINFO_PERMISSION_MASK | \
					  SGX_SECINFO_PAGE_TYPE_MASK)

/**
 * struct sgx_secinfo - describes attributes of an EPC page
 * @flags:	permissions and type
 *
 * Used together with ENCLS leaves that add or modify an EPC page to an
 * enclave to define page permissions and type.
 */
struct sgx_secinfo {
	uint64_t flags;
	uint8_t reserved[56];
} __packed __aligned(64);

#define SGX_PCMD_RESERVED_SIZE 40

/**
 * struct sgx_pcmd - Paging Crypto Metadata (PCMD)
 * @enclave_id:	enclave identifier
 * @mac:	MAC over PCMD, page contents and isvsvn
 *
 * PCMD is stored for every swapped page to the regular memory. When ELDU loads
 * the page back it recalculates the MAC by using a isvsvn number stored in a
 * VA page. Together these two structures bring integrity and rollback
 * protection.
 */
struct sgx_pcmd {
	struct sgx_secinfo secinfo;
	uint64_t enclave_id;
	uint8_t reserved[SGX_PCMD_RESERVED_SIZE];
	uint8_t mac[16];
} __packed __aligned(128);

#define SGX_SIGSTRUCT_RESERVED1_SIZE 84
#define SGX_SIGSTRUCT_RESERVED2_SIZE 20
#define SGX_SIGSTRUCT_RESERVED3_SIZE 32
#define SGX_SIGSTRUCT_RESERVED4_SIZE 12

/**
 * struct sgx_sigstruct_header -  defines author of the enclave
 * @header1:		constant byte string
 * @type:		bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero
 * @vendor:		must be either 0x0000 or 0x8086
 * @date:		YYYYMMDD in BCD
 * @header2:		costant byte string
 * @swdefined:		software defined value
 */
struct sgx_sigstruct_header {
	uint8_t header1[12];
	uint32_t type;
	uint32_t vendor;
	uint32_t date;
	uint8_t header2[16];
	uint32_t swdefined;
	uint8_t reserved1[84];
} __packed;

/**
 * struct sgx_sigstruct_body - defines contents of the enclave
 * @miscselect:		additional information stored to an SSA frame
 * @misc_mask:		required miscselect in SECS
 * @attributes:		attributes for enclave
 * @xfrm:		XSave-Feature Request Mask (subset of XCR0)
 * @attributes_mask:	required attributes in SECS
 * @xfrm_mask:		required XFRM in SECS
 * @mrenclave:		SHA256-hash of the enclave contents
 * @isvprodid:		a user-defined value that is used in key derivation
 * @isvsvn:		a user-defined value that is used in key derivation
 */
struct sgx_sigstruct_body {
	uint32_t miscselect;
	uint32_t misc_mask;
	uint8_t reserved2[20];
	uint64_t attributes;
	uint64_t xfrm;
	uint64_t attributes_mask;
	uint64_t xfrm_mask;
	uint8_t mrenclave[32];
	uint8_t reserved3[32];
	uint16_t isvprodid;
	uint16_t isvsvn;
} __packed;

/**
 * struct sgx_sigstruct - an enclave signature
 * @header:		defines author of the enclave
 * @modulus:		the modulus of the public key
 * @exponent:		the exponent of the public key
 * @signature:		the signature calculated over the fields except modulus,
 * @body:		defines contents of the enclave
 * @q1:			a value used in RSA signature verification
 * @q2:			a value used in RSA signature verification
 *
 * Header and body are the parts that are actual signed. The remaining fields
 * define the signature of the enclave.
 */
struct sgx_sigstruct {
	struct sgx_sigstruct_header header;
	uint8_t modulus[SGX_MODULUS_SIZE];
	uint32_t exponent;
	uint8_t signature[SGX_MODULUS_SIZE];
	struct sgx_sigstruct_body body;
	uint8_t reserved4[12];
	uint8_t q1[SGX_MODULUS_SIZE];
	uint8_t q2[SGX_MODULUS_SIZE];
} __packed;

struct sgx_einittoken_payload {
	uint32_t valid;
	uint32_t reserved1[11];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t mrenclave[32];
	uint8_t reserved2[32];
	uint8_t mrsigner[32];
	uint8_t reserved3[32];
};

struct sgx_einittoken {
	struct sgx_einittoken_payload payload;
	uint8_t cpusvnle[16];
	uint16_t isvprodidle;
	uint16_t isvsvnle;
	uint8_t reserved2[24];
	uint32_t maskedmiscselectle;
	uint64_t maskedattributesle;
	uint64_t maskedxfrmle;
	uint8_t keyid[32];
	uint8_t mac[16];
};

#define SGX_LAUNCH_TOKEN_SIZE 304

#define SGX_TARGET_INFO_SIZE 512

struct sgx_target_info {
	uint8_t mrenclave[32];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t cetattributes;
	uint8_t reserved1;
	uint16_t config_svn;
	uint32_t miscselect;
	uint8_t reserved2[8];
	uint32_t config_id[16];
	uint8_t reserved3[384];
} __packed __aligned(SGX_TARGET_INFO_SIZE);
static_assert(sizeof(struct sgx_target_info) == SGX_TARGET_INFO_SIZE,
	      "incorrect size of sgx_target_info");

#define SGX_REPORT_DATA_SIZE 64

struct sgx_report_data {
	uint8_t report_data[SGX_REPORT_DATA_SIZE];
} __packed __aligned(128);
static_assert(sizeof(struct sgx_report_data) == 128,
	      "incorrect size of sgx_report_data");

struct sgx_report_body {
	uint8_t cpusvn[16];
	uint32_t miscselect;
	uint8_t cetattributes;
	uint8_t reserved1[11];
	uint16_t isv_ext_prod_id[8];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t mrenclave[32];
	uint8_t reserved2[32];
	uint8_t mrsigner[32];
	uint8_t reserved3[32];
	uint32_t config_id[16];
	uint16_t isv_prod_id;
	uint16_t isv_svn;
	uint16_t config_svn;
	uint8_t reserved4[42];
	uint8_t isv_family_id[16];
	uint8_t report_data[64];
} __packed;
static_assert(sizeof(struct sgx_report_body) == 384,
	      "incorrect size of sgx_report_body");

#define SGX_REPORT_SIZE 432

struct sgx_report {
	struct sgx_report_body body;
	uint8_t key_id[32];
	uint8_t mac[16];
} __packed __aligned(512);
static_assert(sizeof(struct sgx_report) == 512, "incorrect size of sgx_report");

/* *INDENT-OFF* */
#endif   /* _ASM_X86_SGX_ARCH_H */
/* *INDENT-ON* */
