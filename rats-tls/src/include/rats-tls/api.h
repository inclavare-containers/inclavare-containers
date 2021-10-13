/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_API_H_
#define _ENCLAVE_API_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <rats-tls/err.h>
#include <openssl/opensslv.h>

#define TLS_TYPE_NAME_SIZE		32
#define ENCLAVE_ATTESTER_TYPE_NAME_SIZE 32
#define ENCLAVE_VERIFIER_TYPE_NAME_SIZE 32
#define CRYPTO_TYPE_NAME_SIZE		32
#define ENCLAVE_SGX_SPID_LENGTH		16
#define SHA256_HASH_SIZE		32

typedef enum {
	RATS_TLS_LOG_LEVEL_DEBUG,
	RATS_TLS_LOG_LEVEL_INFO,
	RATS_TLS_LOG_LEVEL_WARN,
	RATS_TLS_LOG_LEVEL_ERROR,
	RATS_TLS_LOG_LEVEL_FATAL,
	RATS_TLS_LOG_LEVEL_NONE,
	RATS_TLS_LOG_LEVEL_MAX,
	RATS_TLS_LOG_LEVEL_DEFAULT = RATS_TLS_LOG_LEVEL_ERROR
} rats_tls_log_level_t;

typedef struct rtls_core_context_t *rats_tls_handle;

typedef enum {
	RATS_TLS_CERT_ALGO_RSA_3072_SHA256,
	RATS_TLS_CERT_ALGO_ECC_256_SHA256,
	RATS_TLS_CERT_ALGO_MAX,
/* FIXME: need to look into why openssl 1.0 cannot work with ECC-256 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RATS_TLS_CERT_ALGO_DEFAULT = RATS_TLS_CERT_ALGO_RSA_3072_SHA256
#else
	RATS_TLS_CERT_ALGO_DEFAULT = RATS_TLS_CERT_ALGO_ECC_256_SHA256
#endif
} rats_tls_cert_algo_t;

typedef struct {
	unsigned int api_version;
	unsigned long flags;
	rats_tls_log_level_t log_level;
	char tls_type[TLS_TYPE_NAME_SIZE];
	char attester_type[ENCLAVE_ATTESTER_TYPE_NAME_SIZE];
	char verifier_type[ENCLAVE_VERIFIER_TYPE_NAME_SIZE];
	char crypto_type[CRYPTO_TYPE_NAME_SIZE];
	rats_tls_cert_algo_t cert_algo;
	unsigned long long enclave_id;

	/* FIXME: SGX EPID quote type specific parameters */
	struct {
		bool valid;
		uint8_t spid[ENCLAVE_SGX_SPID_LENGTH];
		bool linkable;
	} quote_sgx_epid;

	/* FIXME: SGX ECDSA quote type specific parameters */
	struct {
		bool valid;
		uint8_t cert_type;
	} quote_sgx_ecdsa;
} rats_tls_conf_t;

typedef struct rtls_sgx_evidence {
	uint8_t *mr_enclave;
	uint8_t *mr_signer;
	uint32_t product_id;
	uint32_t security_version;
	uint8_t *attributes;
	size_t collateral_size;
	char *collateral;
} rtls_sgx_evidence_t;

typedef struct rtls_tdx_evidence {
	/* TODO */
} rtls_tdx_evidence_t;

/* The public_key, user_data_size and user_data are needed to include in hash. */
typedef struct ehd {
	void *public_key;
	int user_data_size;
	char *user_data;
	int unhashed_size;
	char *unhashed;
} ehd_t;

typedef enum { SGX_ECDSA = 1, TDX } enclave_evidence_type_t;

typedef struct rtls_evidence {
	enclave_evidence_type_t type;
	ehd_t ehd;
	int quote_size;
	char *quote;
	union {
		rtls_sgx_evidence_t sgx;
		rtls_tdx_evidence_t tdx;
	};
} rtls_evidence_t;

#define RATS_TLS_API_VERSION_1	1
#define RATS_TLS_API_VERSION_MAX	RATS_TLS_API_VERSION_1
#define RATS_TLS_API_VERSION_DEFAULT RATS_TLS_API_VERSION_1

#define RATS_TLS_CONF_FLAGS_GLOBAL_MASK_SHIFT      0
#define RATS_TLS_CONF_FLAGS_PRIVATE_MASK_SHIFT     32
#define RATS_TLS_CONF_FLAGS_VERENFORCED_MASK_SHIFT 33

#define RATS_TLS_CONF_FLAGS_GLOBAL_MASK          (RATS_TLS_CONF_FLAGS_GLOBAL_MASK << RATS_TLS_CONF_FLAGS_PRIVATE_MASK_SHIFT

#define RATS_TLS_CONF_FLAGS_MUTUAL	   (1UL << RATS_TLS_CONF_FLAGS_GLOBAL_MASK_SHIFT)
#define RATS_TLS_CONF_FLAGS_SERVER	   (1UL << RATS_TLS_CONF_FLAGS_PRIVATE_MASK_SHIFT)
#define RATS_TLS_CONF_VERIFIER_ENFORCED (1UL << RATS_TLS_CONF_FLAGS_VERENFORCED_MASK_SHIFT)

typedef int (*rats_tls_callback_t)(void *);

rats_tls_err_t rats_tls_init(const rats_tls_conf_t *conf, rats_tls_handle *handle);
rats_tls_err_t rats_tls_set_verification_callback(rats_tls_handle *handle,
							rats_tls_callback_t user_callback);
rats_tls_err_t rats_tls_negotiate(rats_tls_handle handle, int fd);
rats_tls_err_t rats_tls_receive(rats_tls_handle handle, void *buf, size_t *buf_size);
rats_tls_err_t rats_tls_transmit(rats_tls_handle handle, void *buf, size_t *buf_size);
rats_tls_err_t rats_tls_cleanup(rats_tls_handle handle);

#endif
