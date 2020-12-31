/*
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
//#include <openssl/conf.h>
//#include <openssl/bio.h>
//#include <openssl/crypto.h>
//#include <openssl/engine.h>
#include <openssl/err.h>
//#include <openssl/evp.h>
//#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <unistd.h>
#include <stdint.h>
#include "sgx.h"
#include "defines.h"

/*
 ************************************************
 * v1.1.X and later implementation
 ************************************************
 */

/*#if OPENSSL_VERSION_NUMBER >= 0x1010000fL

EVP_MD_CTX* X_EVP_MD_CTX_new() {
	return EVP_MD_CTX_new();
}

void X_EVP_MD_CTX_free(EVP_MD_CTX* ctx) {
	EVP_MD_CTX_free(ctx);
}
*/
/*
const EVP_MD *X_EVP_dss() {
	return NULL;
}

const EVP_MD *X_EVP_dss1() {
	return NULL;
}

const EVP_MD *X_EVP_sha() {
	return NULL;
}
#endif
*/
/*
 ************************************************
 * v1.0.X implementation
 ************************************************
 */
//#if OPENSSL_VERSION_NUMBER < 0x1010000fL

EVP_MD_CTX* X_EVP_MD_CTX_new() {
	return EVP_MD_CTX_create();
}

void X_EVP_MD_CTX_free(EVP_MD_CTX* ctx) {
	EVP_MD_CTX_destroy(ctx);
}

//const EVP_MD *X_EVP_dss() {
//	return EVP_dss();
//}

//const EVP_MD *X_EVP_dss1() {
//	return EVP_dss1();
//}

//const EVP_MD *X_EVP_sha() {
//	return EVP_sha();
//}
//#endif

/*
const EVP_MD *X_EVP_get_digestbyname(const char *name) {
	return EVP_get_digestbyname(name);
}

const EVP_MD *X_EVP_md_null() {
	return EVP_md_null();
}

const EVP_MD *X_EVP_ripemd160() {
	return EVP_ripemd160();
}
*/

const EVP_MD *X_EVP_md5() {
	return EVP_md5();
}

const EVP_MD *X_EVP_md4() {
	return EVP_md4();
}

const EVP_MD *X_EVP_sha224() {
	return EVP_sha224();
}

const EVP_MD *X_EVP_sha1() {
	return EVP_sha1();
}

const EVP_MD *X_EVP_sha256() {
	return EVP_sha256();
}

const EVP_MD *X_EVP_sha384() {
	return EVP_sha384();
}

const EVP_MD *X_EVP_sha512() {
	return EVP_sha512();
}

int X_EVP_MD_size(const EVP_MD *md) {
	return EVP_MD_size(md);
}

int X_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
	return EVP_DigestInit_ex(ctx, type, impl);
}

int X_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
	return EVP_DigestUpdate(ctx, d, cnt);
}

int X_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) {
	return EVP_DigestFinal_ex(ctx, md, s);
}

/*uint32_t X_Sgx_Calc_Ssaframesize(uint32_t miscselect, uint64_t xfrm) {
	return sgx_calc_ssaframesize(miscselect, xfrm);
}*/

/*
int X_EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
	return EVP_SignInit(ctx, type);
}

int X_EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt) {
	return EVP_SignUpdate(ctx, d, cnt);
}

EVP_PKEY *X_EVP_PKEY_new(void) {
	return EVP_PKEY_new();
}

void X_EVP_PKEY_free(EVP_PKEY *pkey) {
	EVP_PKEY_free(pkey);
}

int X_EVP_PKEY_size(EVP_PKEY *pkey) {
	return EVP_PKEY_size(pkey);
}

struct rsa_st *X_EVP_PKEY_get1_RSA(EVP_PKEY *pkey) {
	return EVP_PKEY_get1_RSA(pkey);
}

int X_EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key) {
	return EVP_PKEY_set1_RSA(pkey, key);
}

int X_EVP_PKEY_assign_charp(EVP_PKEY *pkey, int type, char *key) {
	return EVP_PKEY_assign(pkey, type, key);
}

int X_EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s, EVP_PKEY *pkey) {
	return EVP_SignFinal(ctx, md, s, pkey);
}

int X_EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
	return EVP_VerifyInit(ctx, type);
}

int X_EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d,
		unsigned int cnt) {
	return EVP_VerifyUpdate(ctx, d, cnt);
}

int X_EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey) {
	return EVP_VerifyFinal(ctx, sigbuf, siglen, pkey);
}

int X_EVP_CIPHER_block_size(EVP_CIPHER *c) {
    return EVP_CIPHER_block_size(c);
}

int X_EVP_CIPHER_key_length(EVP_CIPHER *c) {
    return EVP_CIPHER_key_length(c);
}

int X_EVP_CIPHER_iv_length(EVP_CIPHER *c) {
    return EVP_CIPHER_iv_length(c);
}

int X_EVP_CIPHER_nid(EVP_CIPHER *c) {
    return EVP_CIPHER_nid(c);
}

int X_EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_block_size(ctx);
}

int X_EVP_CIPHER_CTX_key_length(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_key_length(ctx);
}

int X_EVP_CIPHER_CTX_iv_length(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_iv_length(ctx);
}

void X_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int padding) {
    //openssl always returns 1 for set_padding
    //hence return value is not checked
    EVP_CIPHER_CTX_set_padding(ctx, padding);
}

const EVP_CIPHER *X_EVP_CIPHER_CTX_cipher(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_cipher(ctx);
}

int X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid) {
	return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
}
*/

/****************sgx attribute related api***********************************/
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
	int cpu_info[4] = { 0, 0, 0, 0 };

	__cpuidex(cpu_info, CPUIID_EXTENDED_FEATURE_FLAGS, 0);

	return !!(cpu_info[2] & 0x40000000);
}

int get_mmap_min_addr(uint64_t *addr)
{
	int fd = open("/proc/sys/vm/mmap_min_addr", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	char buf[12];
	ssize_t sz = read(fd, buf, sizeof(buf));
	close(fd);

	if (sz < 0 || sz == sizeof(buf)) {
		perror("read");
		return -1;
	}

	*addr = (uint64_t) atol((const char *) buf);

	return 0;
}

uint64_t calc_enclave_offset(uint64_t mmap_min_addr,
			     bool null_dereference_protection)
{
	uint64_t encl_offset;

	if (mmap_min_addr) {
		/* OOT driver cannot enable enclave dereference protection
		 * if vm.mmap_min_addr is set to non-zero. In this case,
		 * load_base - encl_base must equal to 0 in order to keep
		 * consistent between mmap area and enclave range.
		 */
		encl_offset = 0;
		/* But there is no such a restriction for in-tree driver.
		 * Currently, null_dereference_protection is always true
		 * if in-tree driver is used.
		 */
		if (null_dereference_protection)
			encl_offset = mmap_min_addr;
	} else {
		/* Enable the enclave dereference protection automatically */
		encl_offset = ENCLAVE_GUARD_AREA_SIZE;
	}

	return encl_offset;
}

bool is_sgx_device(const char *dev)
{
	struct stat st;
	int rc;

	rc = stat(dev, &st);
	if (!rc) {
		if ((st.st_mode & S_IFCHR) && (major(st.st_rdev) == 10))
			return true;
	}

	return false;
}

bool is_oot_kernel_driver(void)
{
	return is_sgx_device("/dev/isgx");
}

uint64_t powtwo(uint64_t sz)
{
	uint64_t tmp;
	for(tmp = 0x1000; tmp < sz; )
		tmp = tmp << 1;
	return tmp;
}

uint64_t alignup(uint64_t sz, uint64_t a)
{
	return (((sz) + (a) - 1) & ~((a) - 1));
}
