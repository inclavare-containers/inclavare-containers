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

uint64_t req_xfrm, req_xfrm_mask;
uint64_t req_attrs, req_attrs_mask;
bool enclave_debug = true;
bool product_enclave = true;

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

static const BIGNUM *get_modulus(RSA * key)
{
	const BIGNUM *n;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	n = key->n;
#else
	RSA_get0_key(key, &n, NULL, NULL);
#endif

	return n;
}

static const BIGNUM *get_exponent(RSA * key)
{
	const BIGNUM *e;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	e = key->e;
#else
	RSA_get0_key(key, NULL, &e, NULL);
#endif

	return e;
}

static RSA *load_sign_key(const char *path)
{
	FILE *f;

	f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "Unable to open %s\n", path);
		return NULL;
	}

	RSA *key = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	fclose(f);
	if (!key)
		return NULL;

	if (BN_num_bytes(get_modulus(key)) != SGX_MODULUS_SIZE) {
		fprintf(stderr, "Invalid key size %d\n",
			BN_num_bytes(get_modulus(key)));
		RSA_free(key);
		return NULL;
	}

	const BIGNUM *e = get_exponent(key);
	if (!BN_is_word(e, 3)) {
		fprintf(stderr, "Exponent must be set to 3.\n");
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
	mrecreate.size = encl_size;

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
			 struct metadata *meta_data)
/* *INDENT-ON* */
{
	FILE *file;
	struct stat sb;
	EVP_MD_CTX *ctx;
	uint64_t flags;
	int rc;
	uint32_t ssa_frame_size;

	ctx = EVP_MD_CTX_create();
	if (!ctx)
		return false;

	file = fopen(path, "r+b");
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

	/* Save metadata area to enclave image, skeleton will act accordingly. */
	if (fseek(file, -sizeof(struct metadata), SEEK_END)) {
		perror("fseek");
		goto out;
	}
	if (fwrite(meta_data, 1, sizeof(struct metadata), file) !=
	    sizeof(struct metadata)) {
		perror("fwrite");
		goto out;
	}
	if (fseek(file, 0L, SEEK_SET)) {
		perror("fseek");
		goto out;
	}

	if (!sb.st_size) {
		fprintf(stderr, "Invalid blob size %lu\n", sb.st_size);
		goto out;
	}

	ssa_frame_size = sgx_calc_ssaframesize(miscselect, xfrm);
	uint64_t mmap_size = sb.st_size + PAGE_SIZE * ssa_frame_size;
	if (meta_data->max_mmap_size) {
		if (meta_data->max_mmap_size < mmap_size) {
			fprintf(stderr,
				"Invalid enclave mmap size %lu, "
				"please set enclave mmap size large than %lu.\n",
				meta_data->max_mmap_size, mmap_size);
			return false;
		}
		mmap_size = meta_data->max_mmap_size;
	}

	if (mmap_size % PAGE_SIZE)
		mmap_size = (mmap_size / PAGE_SIZE + 1) * PAGE_SIZE;

	if (meta_data->null_dereference_protection && meta_data->mmap_min_addr
	    && is_legacy_oot_kernel_driver()) {
		fprintf(stderr,
			"Cannot protect enclave against null dereference attack "
			"when vm.mmap_min_addr is not configured of 0 in OOT driver.\n");
		return false;
	}

	uint64_t encl_offset;
	{
		// *INDENT-OFF*
		encl_offset = calc_enclave_offset(meta_data->mmap_min_addr,
						  meta_data->null_dereference_protection);
		// *INDENT-ON*
	}
	uint64_t encl_size = pow2(encl_offset + mmap_size);
	void *bin = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
			 fileno(file), 0);
	if (bin == MAP_FAILED) {
		fprintf(stderr, "mmap() %s failed, errno=%d.\n", path, errno);
		goto out;
	}

	struct sgx_tcs *tcs = bin;
	/* SSA frame is located right behind encl.bin */
	tcs->ssa_offset = encl_offset + align_up(sb.st_size, PAGE_SIZE);
	tcs->entry_offset += encl_offset;
	if (!mrenclave_ecreate(ctx, ssa_frame_size, encl_size))
		goto out;

	/* Load TCS page and encl.bin into enclave */
	uint64_t offset;
	uint64_t bin_off = 0;
	for (offset = encl_offset; offset < encl_offset + sb.st_size;
	     offset += PAGE_SIZE) {
		if (offset == encl_offset)
			flags = SGX_SECINFO_TCS;
		else
			flags = SGX_SECINFO_REG | SGX_SECINFO_R |
				SGX_SECINFO_W | SGX_SECINFO_X;

		if (!mrenclave_eadd(ctx, offset, flags))
			goto out;

		if (!mrenclave_eextend(ctx, offset, bin + bin_off))
			goto out;

		bin_off += PAGE_SIZE;
	}

	/* Load SSA frame and padding into enclave */
	uint8_t data[PAGE_SIZE];
	memset(data, 0, sizeof(data));

	flags = SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_X;

	/* offset now begins from SSA frame */
	for (; offset < encl_offset + mmap_size; offset += PAGE_SIZE) {
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

	int len = BN_bn2bin(ctx.q1, q1);
	/* convert to little endian */
	reverse_bytes(q1, len);
	len = BN_bn2bin(ctx.q2, q2);
	reverse_bytes(q2, len);

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

static bool save_tbs_sigstruct(const struct sgx_sigstruct *sigstruct,
			       const char *path)
{
	FILE *f = fopen(path, "wb");

	if (!f) {
		fprintf(stderr, "Unable to open %s\n", path);
		return false;
	}

	fwrite(&sigstruct->header, sizeof(sigstruct->header), 1, f);
	fwrite(&sigstruct->body, sizeof(sigstruct->body), 1, f);
	fclose(f);
	return true;
}

// *INDENT-OFF*
static int calc_sgx_attributes(uint64_t *ret_attrs, uint64_t *ret_attrs_mask)
{
	/* skeleton doesn't support 32-bit mode */
	uint64_t enforced_pattern = SGX_ATTR_MODE64BIT;

#ifdef CONFIG_EINITTOKENKEY
	enforced_pattern |= SGX_ATTR_EINITTOKENKEY;
#endif
	if (enclave_debug)
		enforced_pattern |= SGX_ATTR_DEBUG;

	if (req_attrs) {
		if (req_attrs & ~SGX_ATTR_ALLOWED_MASK) {
			fprintf(stderr,
				"Invalid option --attrs. The unsupported attributes %#lx are set.\n",
				req_attrs & ~SGX_ATTR_ALLOWED_MASK);
			return -1;
		}

		if ((req_attrs & enforced_pattern) != enforced_pattern) {
			fprintf(stderr,
				"Invalid option --attrs. The bitmap %#lx must be set.\n",
				enforced_pattern & ~req_attrs);
			return -1;
		}

		if (!req_attrs_mask)
			req_attrs_mask = req_attrs;
	}

	if (req_attrs_mask) {
		if ((req_attrs_mask & enforced_pattern) != enforced_pattern) {
			fprintf(stderr,
				"Invalid option --attrs-mask. The bitmap %#lx must be set.\n",
				enforced_pattern & ~req_attrs_mask);
			return -1;
		}

		if (!req_attrs)
			req_attrs = req_attrs_mask;
	}

	if (req_attrs) {
		/*
		 * Check whether --attrs plus --attrs-mask conflicts with
		 * enclave_debug. Note that the conflict with debug enclave can
		 * be detected prior to reaching here with
		 * enclave_debug && !(req_attrs & req_attrs_mask & SGX_ATTR_DEBUG)
		 * so only the conflict with produce enclave is checked here.
		 */

		if (!enclave_debug &&
		    (req_attrs & req_attrs_mask & SGX_ATTR_DEBUG)) {
			fprintf(stderr,
				"--attrs & --attrs-mask conflicts with product enclave.\n");
			return -1;
		}

		*ret_attrs = req_attrs;
		*ret_attrs_mask = req_attrs_mask;

		return 0;
	}

	uint64_t attrs = enforced_pattern;
	uint64_t attrs_mask = enforced_pattern;

	if (!enclave_debug) {
		attrs &= ~SGX_ATTR_DEBUG;
		attrs_mask |= SGX_ATTR_DEBUG;
	}

	*ret_attrs = attrs;
	*ret_attrs_mask = attrs_mask;

	return 0;
}

static int calc_sgx_xfrm(uint64_t *ret_xfrm, uint64_t *ret_xfrm_mask)
{
	uint64_t calc_xfrm, calc_xfrm_mask;

	get_sgx_xfrm_by_cpuid(&calc_xfrm);
	calc_xfrm_mask = calc_xfrm;

	const uint64_t enforced_pattern = SGX_XFRM_LEGACY;

	if (req_xfrm) {
		if ((req_xfrm & enforced_pattern) != enforced_pattern) {
			fprintf(stderr,
				"Invalid option --xfrm. The minimum bits %#lx are not set.\n",
				enforced_pattern & ~req_xfrm);
			return -1;
		}

		if (!req_xfrm_mask)
			req_xfrm_mask = req_xfrm;

		calc_xfrm = req_xfrm;
	}

	if (req_xfrm_mask) {
		if ((req_xfrm_mask & enforced_pattern) != enforced_pattern) {
			fprintf(stderr,
				"Invalid option --xfrm-mask. The minimum bits %#lx are not set.\n",
				enforced_pattern & ~req_xfrm_mask);
			return -1;
		}

		if (!req_xfrm)
			calc_xfrm = req_xfrm = req_xfrm_mask;

		calc_xfrm_mask = req_xfrm_mask;
	}

	*ret_xfrm = calc_xfrm;
	*ret_xfrm_mask = calc_xfrm_mask;

	return 0;
}
// *INDENT-ON*

int main(int argc, char **argv)
{
	uint64_t mmap_min_addr;

	if (get_mmap_min_addr(&mmap_min_addr)) {
		fprintf(stderr, "failed to get vm.mmap_min_addr\n");
		return -1;
	}

	uint8_t header1[12] = {6, 0, 0, 0, 0xe1, 0, 0, 0, 0, 0, 1, 0};
	uint8_t header2[16] = {1, 1, 0, 0, 0x60, 0, 0, 0, 0x60, 0, 0, 0, 1, 0, 0, 0};
	struct sgx_sigstruct ss;
	const char *program;
	int opt;
	RSA *sign_key;
	struct metadata meta_data;
	char *const short_options = "NDs:x:a:nm:";
	struct option long_options[] = {
		{"no-debugger", no_argument, NULL, 'N'},
		{"debug-enclave", no_argument, NULL, 'D'},
		{"mmap-size", required_argument, NULL, 's'},
		{"xfrm", required_argument, NULL, 'x'},
		{"attrs", required_argument, NULL, 'a'},
		{"xfrm-mask", required_argument, NULL, 'X'},
		{"attrs-mask", required_argument, NULL, 'A'},
		{"null_dereference_protection", no_argument, NULL, 'n'},
		{"mmap_min_addr", required_argument, NULL, 'm'},
		{0, 0, 0, 0}
	};

	program = argv[0];
	memset(&meta_data, 0, sizeof(struct metadata));
	meta_data.mmap_min_addr = mmap_min_addr;

	do {
		opt = getopt_long(argc, argv, short_options, long_options,
				  NULL);
		switch (opt) {
		case 'N':
			enclave_debug = false;
			break;
		case 'D':
			product_enclave = false;
			break;
		case 's':
			meta_data.max_mmap_size = atoi(optarg);
			break;
		case 'x':
			req_xfrm = strtol(optarg, NULL, 16);
			break;
		case 'X':
			req_xfrm_mask = strtol(optarg, NULL, 16);
			break;
		case 'a':
			req_attrs = strtol(optarg, NULL, 16);
			break;
		case 'A':
			req_attrs_mask = strtol(optarg, NULL, 16);
			break;
		case 'n':
			meta_data.null_dereference_protection = true;
			break;
		case 'm':
			meta_data.mmap_min_addr = strtol(optarg, NULL, 16);
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
	memcpy(ss.header.header1, header1, sizeof(ss.header.header1));
	memcpy(ss.header.header2, header2, sizeof(ss.header.header2));

	ss.header.date = get_build_date();

	if (!product_enclave)
		ss.header.type = 1 << 31;

	if (calc_sgx_attributes(&ss.body.attributes, &ss.body.attributes_mask))
		return -1;

	if (calc_sgx_xfrm(&ss.body.xfrm, &ss.body.xfrm_mask))
		return -1;

	ss.body.miscselect = get_sgx_miscselect_by_cpuid();

	/* sanity check only */
	if (check_crypto_errors())
		exit(1);

	sign_key = load_sign_key(argv[0]);
	if (!sign_key)
		goto out;

	if (BN_bn2bin(get_modulus(sign_key), ss.modulus) != SGX_MODULUS_SIZE)
		goto out;

	// *INDENT-OFF*
	if (BN_bn2bin(get_exponent(sign_key), (unsigned char *) &ss.exponent) != SGX_EXPONENT_SIZE)
		goto out;
	// *INDENT-OFF*

	/* *INDENT-OFF* */
	if (!measure_encl(argv[1], ss.body.mrenclave, ss.body.miscselect,
			  ss.body.xfrm, &meta_data))
		goto out;
	/* *INDENT-ON* */

	if (!sign_encl(&ss, sign_key, ss.signature))
		goto out;

	if (!calc_q1q2(ss.signature, ss.modulus, ss.q1, ss.q2))
		goto out;

	/* convert to little endian */
	reverse_bytes(ss.signature, SGX_MODULUS_SIZE);
	reverse_bytes(ss.modulus, SGX_MODULUS_SIZE);

	if (argv[3] && !save_tbs_sigstruct(&ss, argv[3]))
		goto out;

	if (!save_sigstruct(&ss, argv[2]))
		goto out;

	exit(0);
out:
	check_crypto_errors();
	exit(1);
}
