/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/err.h>
#include "internal/core.h"
#include "internal/tls_wrapper.h"
#include "internal/enclave_quote.h"
#include "internal/crypto_wrapper.h"

/* The global configurations present by /opt/enclave-tls/config.toml */
etls_core_context_t global_core_context;
/* The global log level used by log.h */
enclave_tls_log_level_t global_log_level = ENCLAVE_TLS_LOG_LEVEL_DEFAULT;

void __attribute__((constructor)) libenclave_tls_init(void)
{
	ETLS_DEBUG("called\n");

	/* Initialize global configurations. It is intend to leave tls_type,
	 * attester_type, verifier_type and crypto_type empty to take the
	 * best guess.
	 */
	global_core_context.config.api_version = ENCLAVE_TLS_API_VERSION_DEFAULT;
	global_core_context.config.log_level = ENCLAVE_TLS_LOG_LEVEL_DEFAULT;
	global_core_context.config.cert_algo = ENCLAVE_TLS_CERT_ALGO_DEFAULT;

	/* TODO: load and parse the global configuration file */

	/* Load all crypto wrapper instances */
	enclave_tls_err_t err = etls_crypto_wrapper_load_all();
	if (err != ENCLAVE_TLS_ERR_NONE)
		ETLS_FATAL("failed to load any crypto wrapper %#x\n", err);

	/* Load all enclave quote instances */
	err = etls_enclave_quote_load_all();
	if (err != ENCLAVE_TLS_ERR_NONE)
		ETLS_FATAL("failed to load any enclave quote %#x\n", err);

	/* Load all tls wrapper instances */
	err = etls_tls_wrapper_load_all();
	if (err != ENCLAVE_TLS_ERR_NONE)
		ETLS_FATAL("failed to load any tls wrapper %#x\n", err);
}
