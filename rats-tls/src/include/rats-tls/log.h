/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_LOG_H_
#define _ENCLAVE_LOG_H_

// clang-format off
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <rats-tls/api.h>
#ifdef SGX
#include <rats-tls/sgx.h>
#elif defined(OCCLUM)
  #define FPRINTF(io, fmt, ...)                  \
	do {                                     \
		fprintf(io, fmt, ##__VA_ARGS__); \
		fflush(io);                      \
	} while (0)
#else
  #define FPRINTF(io, fmt, ...)                  \
	do {                                     \
		fprintf(io, fmt, ##__VA_ARGS__); \
	} while (0)
#endif

extern rats_tls_log_level_t global_log_level;

#define RTLS_FATAL(fmt, ...)                               \
	do {                                               \
		__PR__(FATAL, stderr, fmt, ##__VA_ARGS__); \
	} while (0)

#define RTLS_ERR(fmt, ...)                                 \
	do {                                               \
		__PR__(ERROR, stderr, fmt, ##__VA_ARGS__); \
	} while (0)

#define RTLS_WARN(fmt, ...)                               \
	do {                                              \
		__PR__(WARN, stdout, fmt, ##__VA_ARGS__); \
	} while (0)

#define RTLS_INFO(fmt, ...)                               \
	do {                                              \
		__PR__(INFO, stdout, fmt, ##__VA_ARGS__); \
	} while (0)

#define RTLS_DEBUG(fmt, ...)                               \
	do {                                               \
		__PR__(DEBUG, stdout, fmt, ##__VA_ARGS__); \
	} while (0)

#ifdef SGX
  #define __PR__(level, io, fmt, ...)                                                 \
	do {                                                                          \
		if (global_log_level <= RATS_TLS_LOG_LEVEL_##level)                \
			printf("[" #level "] %s()@L%d: " fmt, __FUNCTION__, __LINE__, \
			       ##__VA_ARGS__);                                        \
	} while (0)
#else
  #define __PR__(level, io, fmt, ...)                                                   \
	do {                                                                            \
		if (global_log_level <= RATS_TLS_LOG_LEVEL_##level) {                \
			if (RATS_TLS_LOG_LEVEL_##level !=                            \
			    RATS_TLS_LOG_LEVEL_DEBUG) {                              \
				FPRINTF(io, "[" #level "] " fmt, ##__VA_ARGS__);        \
			} else {                                                        \
				time_t __t__ = time(NULL);                              \
				struct tm __loc__;                                      \
				localtime_r(&__t__, &__loc__);                          \
				char __buf__[64];                                       \
				strftime(__buf__, sizeof(__buf__), "%a %b %e %T %Z %Y", \
					 &__loc__);                                     \
				FPRINTF(io, "%s: [" #level "] %s()@L%d: " fmt, __buf__, \
					__FUNCTION__, __LINE__, ##__VA_ARGS__);         \
			}                                                               \
		}                                                                       \
	} while (0)
#endif
// clang-format on

#endif
