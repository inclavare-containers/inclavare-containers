/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <stdlib.h>
#ifndef SGX
#include <dlfcn.h>
#include <strings.h>
#include <dirent.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "enclave-tls/api.h"
#include "enclave-tls/log.h"
#include "internal/core.h"
#include "err.h"

#ifdef SGX
#include "etls_t.h"

extern void libcrypto_wrapper_nullcrypto_init(void);
extern void libcrypto_wrapper_openssl_init(void);
extern void libattester_null_init(void);
extern void libverifier_null_init(void);
extern void libattester_sgx_ecdsa_init(void);
extern void libverifier_sgx_ecdsa_init(void);
extern void libverifier_sgx_ecdsa_qve_init(void);
extern void libattester_sgx_la_init(void);
extern void libverifier_sgx_la_init(void);
extern void libtls_wrapper_nulltls_init(void);
extern void libtls_wrapper_openssl_init(void);
#endif
//clang-format on

#ifdef SGX
void etls_exit(void)
{
        ocall_exit();
}

enclave_tls_log_level_t etls_loglevel_getenv(const char *name)
{
	char *log_level_str = NULL;
	size_t log_level_len = 32;

	log_level_str = calloc(1, log_level_len);
        if (!log_level_str) {
                ETLS_ERR("failed to calloc log level string\n");
                return -1;
        }

	ocall_getenv(name, log_level_str, log_level_len);
	if (log_level_str) {
		if (!strcmp(log_level_str, "debug") || !strcmp(log_level_str, "DEBUG")) {
                        free(log_level_str);
			return ENCLAVE_TLS_LOG_LEVEL_DEBUG;
                } else if (!strcmp(log_level_str, "info") || !strcmp(log_level_str, "INFO")) {
                        free(log_level_str);
			return ENCLAVE_TLS_LOG_LEVEL_INFO;
                } else if (!strcmp(log_level_str, "warn") || !strcmp(log_level_str, "WARN")) {
                        free(log_level_str);
			return ENCLAVE_TLS_LOG_LEVEL_WARN;
                } else if (!strcmp(log_level_str, "error") || !strcmp(log_level_str, "ERROR")) {
                        free(log_level_str);
			return ENCLAVE_TLS_LOG_LEVEL_ERROR;
                } else if (!strcmp(log_level_str, "fatal") || !strcmp(log_level_str, "FATAL")) {
                        free(log_level_str);
			return ENCLAVE_TLS_LOG_LEVEL_FATAL;
                } else if (!strcmp(log_level_str, "off") || !strcmp(log_level_str, "OFF")) {
                        free(log_level_str);
			return ENCLAVE_TLS_LOG_LEVEL_NONE;
                }
	}

	return ENCLAVE_TLS_LOG_LEVEL_DEFAULT;
}

enclave_tls_err_t etls_instance_init(const char *name, __attribute__((unused)) const char *realpath,
				     __attribute__((unused)) void **handle)
{
        enclave_tls_err_t err;

	if (!strcmp(name, "nullcrypto")) {
		libcrypto_wrapper_nullcrypto_init();
                err = etls_enclave_crypto_post_init(name, NULL);
                if (err != ENCLAVE_TLS_ERR_NONE)
                        return err;
        } else if (!strcmp(name, "nullattester")) {
		libattester_null_init();
                err = etls_enclave_attester_post_init(name, NULL);
                if (err != ENCLAVE_TLS_ERR_NONE)
                        return err;
        } else if (!strcmp(name, "nullverifier")) {
		libverifier_null_init();
                err = etls_enclave_verifier_post_init(name, NULL);
                if (err != ENCLAVE_TLS_ERR_NONE)
                        return err;
        } else if (!strcmp(name, "sgx_ecdsa")) {
		libattester_sgx_ecdsa_init();
		libverifier_sgx_ecdsa_init();
                err = etls_enclave_attester_post_init(name, NULL);
                if (err != ENCLAVE_TLS_ERR_NONE)
                        return err;
                err = etls_enclave_verifier_post_init(name, NULL);
                if (err != ENCLAVE_TLS_ERR_NONE)
                        return err;
	} else if (!strcmp(name, "sgx_ecdsa_qve")) {
		libverifier_sgx_ecdsa_qve_init();
                err = etls_enclave_verifier_post_init(name, NULL);
                if (err != ENCLAVE_TLS_ERR_NONE)
                        return err;
        } else if (!strcmp(name, "sgx_la")) {
		libattester_sgx_la_init();
		libverifier_sgx_la_init();
                 err = etls_enclave_attester_post_init(name, NULL);
                 if (err != ENCLAVE_TLS_ERR_NONE)
                         return err;
                 err = etls_enclave_verifier_post_init(name, NULL);
                 if (err != ENCLAVE_TLS_ERR_NONE)
                         return err;
	} else if (!strcmp(name, "nulltls")) {
		libtls_wrapper_nulltls_init();
                err = etls_enclave_tls_post_init(name, NULL);
                if (err != ENCLAVE_TLS_ERR_NONE)
                        return err;
        } else if (!strcmp(name, "openssl")) {
		libtls_wrapper_openssl_init();
		libcrypto_wrapper_openssl_init();
                err = etls_enclave_tls_post_init(name, NULL);
                if (err != ENCLAVE_TLS_ERR_NONE)
                        return err;
                err = etls_enclave_crypto_post_init(name, NULL);
                if (err != ENCLAVE_TLS_ERR_NONE)
                        return err;
	} else
		return ENCLAVE_TLS_ERR_NO_NAME;

	return ENCLAVE_TLS_ERR_NONE;
}

ssize_t etls_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;
	int sgx_status = ocall_write(&rc, fd, buf, count);
	if (SGX_SUCCESS != sgx_status) {
		ETLS_ERR("sgx failed to write data, sgx status: 0x%04x\n", sgx_status);
	}

	return rc;
}

ssize_t etls_read(int fd, void *buf, size_t count)
{
	ssize_t rc;
	int sgx_status = ocall_read(&rc, fd, buf, count);
	if (SGX_SUCCESS != sgx_status) {
		ETLS_ERR("sgx failed to read data, sgx status: 0x%04x\n", sgx_status);
	}

	return rc;
}

uint64_t etls_opendir(const char *name)
{
	uint64_t dir;

	int sgx_status = ocall_opendir(&dir, name);
	if (sgx_status != SGX_SUCCESS) {
		ETLS_ERR("sgx failed to open %s, sgx status: 0x%04x\n", name, sgx_status);
	}

	return dir;
}

int etls_readdir(uint64_t dirp, etls_dirent **ptr)
{
	int ret = 0;

	*ptr = (etls_dirent *)calloc(1, sizeof(etls_dirent));
        if (!ptr) {
                ETLS_ERR("failed to calloc memory in etls_readdir\n");
                return -1;
        }
	ocall_readdir(&ret, dirp, *ptr);

	return ret;
}

int etls_closedir(uint64_t dir)
{
	int ret = 0;
	ocall_closedir(&ret, dir);

	return ret;
}
#else
void etls_exit(void)
{
        exit(EXIT_FAILURE);
}

enclave_tls_log_level_t etls_loglevel_getenv(const char *name)
{
	char *log_level_str = log_level_str = getenv(name);
	if (log_level_str) {
		if (!strcasecmp(log_level_str, "debug"))
			return ENCLAVE_TLS_LOG_LEVEL_DEBUG;
		else if (!strcasecmp(log_level_str, "info"))
			return ENCLAVE_TLS_LOG_LEVEL_INFO;
		else if (!strcasecmp(log_level_str, "warn"))
			return ENCLAVE_TLS_LOG_LEVEL_WARN;
		else if (!strcasecmp(log_level_str, "error"))
			return ENCLAVE_TLS_LOG_LEVEL_ERROR;
		else if (!strcasecmp(log_level_str, "fatal"))
			return ENCLAVE_TLS_LOG_LEVEL_FATAL;
		else if (!strcasecmp(log_level_str, "off"))
			return ENCLAVE_TLS_LOG_LEVEL_NONE;
	}

	return ENCLAVE_TLS_LOG_LEVEL_DEFAULT;
}

enclave_tls_err_t etls_instance_init(const char *name, __attribute__((unused)) const char *realpath,
				     __attribute__((unused)) void **handle)
{
	*handle = dlopen(realpath, RTLD_LAZY);
	if (*handle == NULL) {
		ETLS_ERR("failed on dlopen(): %s\n", dlerror());
		return -ENCLAVE_TLS_ERR_DLOPEN;
	}

	return ENCLAVE_TLS_ERR_NONE;
}

ssize_t etls_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;
	rc = write(fd, buf, count);

	return rc;
}

ssize_t etls_read(int fd, void *buf, size_t count)
{
	ssize_t rc;
	rc = read(fd, buf, count);

	return rc;
}

uint64_t etls_opendir(const char *name)
{
	uint64_t dir;
	dir = (uint64_t)opendir(name);

	return dir;
}

int etls_readdir(uint64_t dirp, etls_dirent **ptr)
{
	int ret = 0;

	*ptr = readdir((DIR *)dirp);
	if (*ptr == NULL)
		ret = 1;

	return ret;
}

int etls_closedir(uint64_t dir)
{
	return closedir((DIR *)dir);
}
#endif
