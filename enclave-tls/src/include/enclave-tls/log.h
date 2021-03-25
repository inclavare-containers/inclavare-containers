/* *INDENT-OFF* */
#ifndef _ENCLAVE_LOG_H_
#define _ENCLAVE_LOG_H_
/* *INDENT-ON* */
#ifndef SGX_ENCLAVE
  #include <time.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <enclave-tls/api.h>
#ifdef SGX_ENCLAVE
  #include <enclave-tls/sgx.h>
#endif

extern enclave_tls_log_level_t global_log_level;

#define ETLS_FATAL(fmt, ...)   \
	do {    \
		__PR__(FATAL, stderr, fmt, ##__VA_ARGS__);      \
		exit(EXIT_FAILURE);     \
	} while (0)

#define ETLS_ERR(fmt, ...)   \
	do {    \
		__PR__(ERROR, stderr, fmt, ##__VA_ARGS__);      \
	} while (0)

#define ETLS_WARN(fmt, ...)  \
	do {    \
		__PR__(WARN, stdout, fmt, ##__VA_ARGS__);    \
	} while (0)

#define ETLS_INFO(fmt, ...)  \
	do {    \
		__PR__(INFO, stdout, fmt, ##__VA_ARGS__);       \
	} while (0)

#define ETLS_DEBUG(fmt, ...) \
	do {    \
		__PR__(DEBUG, stdout, fmt, ##__VA_ARGS__);      \
	} while (0)

#ifdef SGX_ENCLAVE
#define __PR__(level, io, fmt, ...)     \
        do {    \
        	printf("[" #level "] %s--%d lines "fmt, __func__, __LINE__, ##__VA_ARGS__); \
	} while (0)
#else
#define __PR__(level, io, fmt, ...)     \
	do {    \
		if (global_log_level <= ENCLAVE_TLS_LOG_LEVEL_##level) {   \
			if (ENCLAVE_TLS_LOG_LEVEL_##level != ENCLAVE_TLS_LOG_LEVEL_DEBUG) {	\
				fprintf(io, "[" #level "] " fmt, ##__VA_ARGS__);	\
			} else {	\
				time_t __t__ = time(NULL);      \
				struct tm __loc__;      \
				localtime_r(&__t__, &__loc__);  \
				char __buf__[64]; \
				strftime(__buf__, sizeof(__buf__), "%a %b %e %T %Z %Y", &__loc__);      \
				fprintf(io, "%s: [" #level "] %s(): " fmt, __buf__, __func__, ##__VA_ARGS__);   \
			}	\
		} \
	} while (0)
#endif

/* *INDENT-OFF* */
#endif
/* *INDENT-ON* */
