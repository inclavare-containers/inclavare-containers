// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-18 Intel Corporation.

#define _GNU_SOURCE
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "defines.h"

#define PAGE_SIZE  4096

struct sgx_sigstruct_payload {
	struct sgx_sigstruct_header header;
	struct sgx_sigstruct_body body;
};

static bool check_crypto_errors(void)
{
	int err;
	bool had_errors = false;
	const char *filename;
	int line;
	char str[256];

	for (;;) {
		if (ERR_peek_error() == 0)
			break;

		had_errors = true;
		err = ERR_get_error_line(&filename, &line);
		ERR_error_string_n(err, str, sizeof(str));
		fprintf(stderr, "crypto: %s: %s:%d\n", str, filename, line);
	}

	return had_errors;
}

static void exit_usage(const char *program)
{
	fprintf(stderr,
		"Usage: %s/sign-le <key> <enclave> <sigstruct>\n", program);
	exit(1);
}

/* *INDENT-OFF* */
static inline const BIGNUM *get_modulus(RSA *key)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	return key->n;
#else
	const BIGNUM *n;

	RSA_get0_key(key, &n, NULL, NULL);
	return n;
#endif
}
/* *INDENT-ON* */

static RSA *load_sign_key(const char *path)
{
	FILE *f;
	RSA *key;

	f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "Unable to open %s\n", path);
		return NULL;
	}
	key = RSA_new();
	if (!PEM_read_RSAPrivateKey(f, &key, NULL, NULL))
		return NULL;
	fclose(f);

	if (BN_num_bytes(get_modulus(key)) != SGX_MODULUS_SIZE) {
		fprintf(stderr, "Invalid key size %d\n",
			BN_num_bytes(get_modulus(key)));
		RSA_free(key);
		return NULL;
	}

	return key;
}

static void reverse_bytes(void *data, int length)
{
	int i = 0;
	int j = length - 1;
	uint8_t temp;
	uint8_t *ptr = data;

	while (i < j) {
		temp = ptr[i];
		ptr[i] = ptr[j];
		ptr[j] = temp;
		i++;
		j--;
	}
}

enum mrtags {
	MRECREATE = 0x0045544145524345,
	MREADD = 0x0000000044444145,
	MREEXTEND = 0x00444E4554584545,
};

/* *INDENT-OFF* */
static bool mrenclave_update(EVP_MD_CTX *ctx, const void *data)
/* *INDENT-ON* */
{
	if (!EVP_DigestUpdate(ctx, data, 64)) {
		fprintf(stderr, "digest update failed\n");
		return false;
	}

	return true;
}

/* *INDENT-OFF* */
static bool mrenclave_commit(EVP_MD_CTX *ctx, uint8_t *mrenclave)
{
	unsigned int size;

	if (!EVP_DigestFinal_ex(ctx, (unsigned char *) mrenclave, &size)) {
		fprintf(stderr, "digest commit failed\n");
		return false;
	}

	if (size != 32) {
		fprintf(stderr, "invalid digest size = %u\n", size);
		return false;
	}

	return true;
}
/* *INDENT-ON* */

struct mrecreate {
	uint64_t tag;
	uint32_t ssaframesize;
	uint64_t size;
	uint8_t reserved[44];
} __attribute__((__packed__));

/* *INDENT-OFF* */
static bool mrenclave_ecreate(EVP_MD_CTX * ctx, uint32_t ssa_frame_size,
			      uint64_t encl_size)
/* *INDENT-ON* */
{
	struct mrecreate mrecreate;

	memset(&mrecreate, 0, sizeof(mrecreate));
	mrecreate.tag = MRECREATE;
	mrecreate.ssaframesize = ssa_frame_size;

	for (mrecreate.size = PAGE_SIZE; mrecreate.size < encl_size;)
		mrecreate.size <<= 1;

	if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		return false;

	return mrenclave_update(ctx, &mrecreate);
}

struct mreadd {
	uint64_t tag;
	uint64_t offset;
	uint64_t flags;		/* SECINFO flags */
	uint8_t reserved[40];
} __attribute__((__packed__));

/* *INDENT-OFF* */
static bool mrenclave_eadd(EVP_MD_CTX *ctx, uint64_t offset, uint64_t flags)
/* *INDENT-ON* */
{
	struct mreadd mreadd;

	memset(&mreadd, 0, sizeof(mreadd));
	mreadd.tag = MREADD;
	mreadd.offset = offset;
	mreadd.flags = flags;

	return mrenclave_update(ctx, &mreadd);
}

struct mreextend {
	uint64_t tag;
	uint64_t offset;
	uint8_t reserved[48];
} __attribute__((__packed__));

/* *INDENT-OFF* */
static bool mrenclave_eextend(EVP_MD_CTX *ctx, uint64_t offset, uint8_t *data)
/* *INDENT-ON* */
{
	struct mreextend mreextend;
	int i;

	for (i = 0; i < PAGE_SIZE; i += 0x100) {
		memset(&mreextend, 0, sizeof(mreextend));
		mreextend.tag = MREEXTEND;
		mreextend.offset = offset + i;

		if (!mrenclave_update(ctx, &mreextend))
			return false;

		if (!mrenclave_update(ctx, &data[i + 0x00]))
			return false;

		if (!mrenclave_update(ctx, &data[i + 0x40]))
			return false;

		if (!mrenclave_update(ctx, &data[i + 0x80]))
			return false;

		if (!mrenclave_update(ctx, &data[i + 0xC0]))
			return false;
	}

	return true;
}

/**
 * measure_encl - measure enclave
 * @path: path to the enclave
 * @mrenclave: measurement
 *
 * Calculates MRENCLAVE. Assumes that the very first page is a TCS page and
 * following pages are regular pages. Does not measure the contents of the
 * enclave as the signing tool is used at the moment only for the launch
 * enclave, which is pass-through (everything gets a token).
 */
/* *INDENT-OFF* */
static bool measure_encl(const char *path, uint8_t *mrenclave,
			 uint32_t miscselect, uint64_t xfrm,
			 uint64_t max_mmap_size)
/* *INDENT-ON* */
{
	FILE *file;
	struct stat sb;
	EVP_MD_CTX *ctx;
	uint64_t flags;
	uint64_t offset;
	uint8_t data[PAGE_SIZE];
	int rc;
	uint32_t ssa_frame_size;

	ctx = EVP_MD_CTX_create();
	if (!ctx)
		return false;

	file = fopen(path, "rb");
	if (!file) {
		perror("fopen");
		EVP_MD_CTX_destroy(ctx);
		return false;
	}

	rc = stat(path, &sb);
	if (rc) {
		perror("stat");
		goto out;
	}

	if (!sb.st_size || sb.st_size & 0xfff) {
		fprintf(stderr, "Invalid blob size %lu\n", sb.st_size);
		goto out;
	}

	ssa_frame_size = sgx_calc_ssaframesize(miscselect, xfrm);
	uint64_t encl_size = sb.st_size + PAGE_SIZE * ssa_frame_size;
	if (max_mmap_size) {
		if (max_mmap_size < encl_size) {
			fprintf(stderr,
				"Invalid enclave mmap size %lu, "
				"please set enclave mmap size large than %lu.\n",
				max_mmap_size, encl_size);
			return false;
		}
		encl_size = max_mmap_size;
	}

	void *bin = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
			 fileno(file), 0);
	if (bin == MAP_FAILED) {
		fprintf(stderr, "mmap() %s failed, errno=%d.\n", path, errno);
		goto out;
	}

	struct sgx_tcs *tcs = bin;
	tcs->ssa_offset = sb.st_size;

	if (!mrenclave_ecreate(ctx, ssa_frame_size, encl_size))
		goto out;

	for (offset = 0; offset < sb.st_size; offset += PAGE_SIZE) {
		if (!offset)
			flags = SGX_SECINFO_TCS;
		else
			flags = SGX_SECINFO_REG | SGX_SECINFO_R |
				SGX_SECINFO_W | SGX_SECINFO_X;

		if (!mrenclave_eadd(ctx, offset, flags))
			goto out;

		memcpy(data, bin + offset, PAGE_SIZE);

		if (!mrenclave_eextend(ctx, offset, data))
			goto out;
	}

	memset(data, 0, sizeof(data));

	flags = SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X;

	if (encl_size % PAGE_SIZE)
		encl_size = (encl_size / PAGE_SIZE + 1) * PAGE_SIZE;
	for (offset = sb.st_size; offset < encl_size; offset += PAGE_SIZE) {
		if (!mrenclave_eadd(ctx, offset, flags))
			goto out;

		if (!mrenclave_eextend(ctx, offset, data))
			goto out;
	}

	if (!mrenclave_commit(ctx, mrenclave))
		goto out;

	munmap(bin, sb.st_size);
	fclose(file);
	EVP_MD_CTX_destroy(ctx);
	return true;
out:
	munmap(bin, sb.st_size);
	fclose(file);
	EVP_MD_CTX_destroy(ctx);
	return false;
}

/**
 * sign_encl - sign enclave
 * @sigstruct: pointer to SIGSTRUCT
 * @key: 3072-bit RSA key
 * @signature: byte array for the signature
 *
 * Calculates EMSA-PKCSv1.5 signature for the given SIGSTRUCT. The result is
 * stored in big-endian format so that it can be further passed to OpenSSL
 * libcrypto functions.
 */
/* *INDENT-OFF* */
static bool sign_encl(const struct sgx_sigstruct *sigstruct, RSA *key,
		      uint8_t *signature)
/* *INDENT-ON* */
{
	struct sgx_sigstruct_payload payload;
	unsigned int siglen;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	bool ret;

	memcpy(&payload.header, &sigstruct->header, sizeof(sigstruct->header));
	memcpy(&payload.body, &sigstruct->body, sizeof(sigstruct->body));

	SHA256((unsigned char *) &payload, sizeof(payload), digest);

	ret = RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature,
		       &siglen, key);

	return ret;
}

struct q1q2_ctx {
	BN_CTX *bn_ctx;
	BIGNUM *m;
	BIGNUM *s;
	BIGNUM *q1;
	BIGNUM *qr;
	BIGNUM *q2;
};

static void free_q1q2_ctx(struct q1q2_ctx *ctx)
{
	BN_CTX_free(ctx->bn_ctx);
	BN_free(ctx->m);
	BN_free(ctx->s);
	BN_free(ctx->q1);
	BN_free(ctx->qr);
	BN_free(ctx->q2);
}

/* *INDENT-OFF* */
static bool alloc_q1q2_ctx(const uint8_t *s, const uint8_t *m,
			   struct q1q2_ctx *ctx)
{
	ctx->bn_ctx = BN_CTX_new();
	ctx->s = BN_bin2bn(s, SGX_MODULUS_SIZE, NULL);
	ctx->m = BN_bin2bn(m, SGX_MODULUS_SIZE, NULL);
	ctx->q1 = BN_new();
	ctx->qr = BN_new();
	ctx->q2 = BN_new();

	if (!ctx->bn_ctx || !ctx->s || !ctx->m || !ctx->q1 || !ctx->qr ||
	    !ctx->q2) {
		free_q1q2_ctx(ctx);
		return false;
	}

	return true;
}

static bool calc_q1q2(const uint8_t *s, const uint8_t *m, uint8_t *q1,
		      uint8_t *q2)
{
	struct q1q2_ctx ctx;

	if (!alloc_q1q2_ctx(s, m, &ctx)) {
		fprintf(stderr, "Not enough memory for Q1Q2 calculation\n");
		return false;
	}

	if (!BN_mul(ctx.q1, ctx.s, ctx.s, ctx.bn_ctx))
		goto out;

	if (!BN_div(ctx.q1, ctx.qr, ctx.q1, ctx.m, ctx.bn_ctx))
		goto out;

	if (BN_num_bytes(ctx.q1) > SGX_MODULUS_SIZE) {
		fprintf(stderr, "Too large Q1 %d bytes\n",
			BN_num_bytes(ctx.q1));
		goto out;
	}

	if (!BN_mul(ctx.q2, ctx.s, ctx.qr, ctx.bn_ctx))
		goto out;

	if (!BN_div(ctx.q2, NULL, ctx.q2, ctx.m, ctx.bn_ctx))
		goto out;

	if (BN_num_bytes(ctx.q2) > SGX_MODULUS_SIZE) {
		fprintf(stderr, "Too large Q2 %d bytes\n",
			BN_num_bytes(ctx.q2));
		goto out;
	}

	BN_bn2bin(ctx.q1, q1);
	BN_bn2bin(ctx.q2, q2);

	free_q1q2_ctx(&ctx);
	return true;
out:
	free_q1q2_ctx(&ctx);
	return false;
}
/* *INDENT-ON* */

static bool save_sigstruct(const struct sgx_sigstruct *sigstruct,
			   const char *path)
{
	FILE *f = fopen(path, "wb");

	if (!f) {
		fprintf(stderr, "Unable to open %s\n", path);
		return false;
	}

	fwrite(sigstruct, sizeof(*sigstruct), 1, f);
	fclose(f);
	return true;
}

int main(int argc, char **argv)
{
	uint64_t header1[2] = { 0x000000E100000006, 0x0000000000010000 };
	uint64_t header2[2] = { 0x0000006000000101, 0x0000000100000060 };
	uint64_t xfrm;
	struct sgx_sigstruct ss;
	const char *program;
	int opt;
	RSA *sign_key;
	bool enclave_debug = true;
	uint64_t max_mmap_size = 0;
	char *const short_options = "ps:";
	struct option long_options[] = {
		{"product", no_argument, NULL, 'p'},
		{"mmap-size", required_argument, NULL, 's'},
		{0, 0, 0, 0}
	};

	program = argv[0];

	do {
		opt = getopt_long(argc, argv, short_options, long_options,
				  NULL);
		switch (opt) {
		case 'p':
			enclave_debug = false;
			break;
		case 's':
			max_mmap_size = atoi(optarg);
			break;
		case -1:
			break;
		default:
			exit_usage(program);
		}
	} while (opt != -1);

	argc -= optind;
	argv += optind;

	if (argc < 3)
		exit_usage(program);

	memset(&ss, 0, sizeof(ss));
	ss.header.header1[0] = header1[0];
	ss.header.header1[1] = header1[1];
	ss.header.header2[0] = header2[0];
	ss.header.header2[1] = header2[1];
	ss.exponent = 3;

#ifndef CONFIG_EINITTOKENKEY
	ss.body.attributes = SGX_ATTR_MODE64BIT;
#else
	ss.body.attributes = SGX_ATTR_MODE64BIT | SGX_ATTR_EINITTOKENKEY;
#endif
	if (enclave_debug)
		ss.body.attributes |= SGX_ATTR_DEBUG;

	get_sgx_xfrm_by_cpuid(&xfrm);
	ss.body.xfrm = xfrm;

	ss.body.attributes_mask = ss.body.attributes;
	ss.body.miscselect = get_sgx_miscselect_by_cpuid();

	/* sanity check only */
	if (check_crypto_errors())
		exit(1);

	sign_key = load_sign_key(argv[0]);
	if (!sign_key)
		goto out;

	BN_bn2bin(get_modulus(sign_key), ss.modulus);

	if (!measure_encl
	    (argv[1], ss.body.mrenclave, ss.body.miscselect, ss.body.xfrm,
	     max_mmap_size))
		goto out;

	if (!sign_encl(&ss, sign_key, ss.signature))
		goto out;

	if (!calc_q1q2(ss.signature, ss.modulus, ss.q1, ss.q2))
		goto out;

	/* convert to little endian */
	reverse_bytes(ss.signature, SGX_MODULUS_SIZE);
	reverse_bytes(ss.modulus, SGX_MODULUS_SIZE);
	reverse_bytes(ss.q1, SGX_MODULUS_SIZE);
	reverse_bytes(ss.q2, SGX_MODULUS_SIZE);

	if (!save_sigstruct(&ss, argv[2]))
		goto out;
	exit(0);
out:
	check_crypto_errors();
	exit(1);
}
