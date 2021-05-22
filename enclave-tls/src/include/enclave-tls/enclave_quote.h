/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_TLS_ENCLAVE_QUOTE_H
#define _ENCLAVE_TLS_ENCLAVE_QUOTE_H

#include <stdint.h>
#include <enclave-tls/compilation.h>
#include <enclave-tls/err.h>
#include <enclave-tls/api.h>
#include <enclave-tls/cert.h>

#define ENCLAVE_QUOTE_TYPE_MAX               32

#define ENCLAVE_QUOTE_API_VERSION_1          1
#define ENCLAVE_QUOTE_API_VERSION_MAX        ENCLAVE_QUOTE_API_VERSION_1
#define ENCLAVE_QUOTE_API_VERSION_DEFAULT    ENCLAVE_QUOTE_API_VERSION_1

#define ENCLAVE_QUOTE_OPTS_FLAGS_SGX_ENCLAVE 1

#define ENCLAVE_QUOTE_FLAGS_DEFAULT          0

typedef struct enclave_quote_ctx             enclave_quote_ctx_t;

typedef struct {
	uint8_t api_version;
	unsigned long flags;
	const char name[QUOTE_TYPE_NAME_SIZE];
	/* Different attester instances may generate the same format of quote,
	 * e.g, sgx_ecdsa and sgx_ecdsa_qve both generate the format "sgx_ecdsa".
	 * By default, the value of type equals to name.
	 */
	char type[QUOTE_TYPE_NAME_SIZE];
	uint8_t priority;

	/* Optional */
	enclave_quote_err_t (*pre_init)(void);
	enclave_quote_err_t (*init)(enclave_quote_ctx_t *ctx,
				    enclave_tls_cert_algo_t algo);
	enclave_quote_err_t (*extend_cert)(enclave_quote_ctx_t *ctx,
					   const enclave_tls_cert_info_t *cert_info);
	enclave_quote_err_t (*collect_evidence)(enclave_quote_ctx_t *ctx,
						attestation_evidence_t *evidence,
						enclave_tls_cert_algo_t algo,
						uint8_t *hash);
	enclave_quote_err_t (*verify_evidence)(enclave_quote_ctx_t *ctx,
					       attestation_evidence_t *evidence,
					       uint8_t *hash, unsigned int hash_len);
	enclave_quote_err_t (*collect_collateral)(enclave_quote_ctx_t *ctx);
	enclave_quote_err_t (*cleanup)(enclave_quote_ctx_t *ctx);
} enclave_quote_opts_t;

struct enclave_quote_ctx {
	enclave_quote_opts_t *opts;
	void *quote_private;
	unsigned long long enclave_id;
	enclave_tls_log_level_t log_level;
	void *handle;

	union {
		struct {
			const char name[QUOTE_TYPE_NAME_SIZE];
			uint8_t spid[ENCLAVE_SGX_SPID_LENGTH];
			bool linkable;
		} sgx_epid;

		struct {
			const char name[QUOTE_TYPE_NAME_SIZE];
			uint8_t cert_type;
			quote_sgx_ecdsa_verification_type_t verification_type;
		} sgx_ecdsa;
	} config;
};

#endif
