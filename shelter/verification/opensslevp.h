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
 *
 */

//#include <stdlib.h>
//#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>

//Digest struct

// EVP methods 
//extern const int X_ED25519_SUPPORT;
//extern int X_EVP_PKEY_ED25519;
//extern const EVP_MD *X_EVP_get_digestbyname(const char *name);
extern EVP_MD_CTX *X_EVP_MD_CTX_new();
extern void X_EVP_MD_CTX_free(EVP_MD_CTX *ctx);
//extern const EVP_MD *X_EVP_md_null();
extern const EVP_MD *X_EVP_md5();
extern const EVP_MD *X_EVP_md4();
extern const EVP_MD *X_EVP_sha();
extern const EVP_MD *X_EVP_sha1();
extern const EVP_MD *X_EVP_dss();
extern const EVP_MD *X_EVP_dss1();
//extern const EVP_MD *X_EVP_ripemd160();
extern const EVP_MD *X_EVP_sha224();
extern const EVP_MD *X_EVP_sha256();
extern const EVP_MD *X_EVP_sha384();
extern const EVP_MD *X_EVP_sha512();
extern int X_EVP_MD_size(const EVP_MD *md);
extern int X_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
extern int X_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
extern int X_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
//extern int X_EVP_SignInit(EVP_MD_CTX *ctx, const EVP_MD *type);
//extern int X_EVP_SignUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
//extern int X_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
//extern int X_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
//extern EVP_PKEY *X_EVP_PKEY_new(void);
//extern void X_EVP_PKEY_free(EVP_PKEY *pkey);
//extern int X_EVP_PKEY_size(EVP_PKEY *pkey);
//extern struct rsa_st *X_EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
//extern int X_EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);
//extern int X_EVP_PKEY_assign_charp(EVP_PKEY *pkey, int type, char *key);
//extern int X_EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s, EVP_PKEY *pkey);
//extern int X_EVP_VerifyInit(EVP_MD_CTX *ctx, const EVP_MD *type);
//extern int X_EVP_VerifyUpdate(EVP_MD_CTX *ctx, const void *d, unsigned int cnt);
//extern int X_EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf, unsigned int siglen, EVP_PKEY *pkey);
//extern int X_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
//extern int X_EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);
//extern int X_EVP_CIPHER_block_size(EVP_CIPHER *c);
//extern int X_EVP_CIPHER_key_length(EVP_CIPHER *c);
//extern int X_EVP_CIPHER_iv_length(EVP_CIPHER *c);
//extern int X_EVP_CIPHER_nid(EVP_CIPHER *c);
//extern int X_EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX *ctx);
//extern int X_EVP_CIPHER_CTX_key_length(EVP_CIPHER_CTX *ctx);
//extern int X_EVP_CIPHER_CTX_iv_length(EVP_CIPHER_CTX *ctx);
//extern void X_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int padding);
//extern const EVP_CIPHER *X_EVP_CIPHER_CTX_cipher(EVP_CIPHER_CTX *ctx);
//extern int X_EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);
//extern int X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
extern void get_sgx_xfrm_by_cpuid(uint64_t *xfrm);
extern uint32_t sgx_calc_ssaframesize(uint32_t miscselect, uint64_t xfrm);
extern uint32_t get_sgx_miscselect_by_cpuid(void);
extern int get_mmap_min_addr(uint64_t *addr);
extern bool is_launch_control_supported(void);
extern uint64_t calc_enclave_offset(uint64_t mmap_min_addr,bool null_dereference_protection);
extern bool is_sgx_device(const char *dev);
extern bool is_oot_kernel_driver(void);
extern uint64_t powtwo(uint64_t sz);
extern uint64_t alignup(uint64_t sz, uint64_t a);
