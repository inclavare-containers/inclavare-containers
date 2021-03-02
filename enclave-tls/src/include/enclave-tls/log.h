/* *INDENT-OFF* */
#ifndef _ENCLAVE_LOG_H_
#define _ENCLAVE_LOG_H_
/* *INDENT-ON* */

#include <time.h>
#include <stdio.h>

#include <enclave-tls/api.h>

extern enclave_tls_log_level_t global_log_level;

#define ETLS_FATAL(fmt, ...)   \
        do {    \
                __PR__(FAULT, stderr, fmt, ##__VA_ARGS__);      \
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

#define __PR__(level, io, fmt, ...)     \
        do {    \
		if (global_log_level <= ENCLAVE_TLS_LOG_LEVEL_##level) {   \
                    time_t __t__ = time(NULL);      \
                    struct tm __loc__;      \
                    localtime_r(&__t__, &__loc__);  \
                    char __buf__[64]; \
                    strftime(__buf__, sizeof(__buf__), "%a %b %e %T %Z %Y", &__loc__);      \
                    fprintf(io, "%s: [" #level "] " fmt, __buf__, ##__VA_ARGS__);   \
		} \
        } while (0)

/* *INDENT-OFF* */
#endif
/* *INDENT-ON* */
