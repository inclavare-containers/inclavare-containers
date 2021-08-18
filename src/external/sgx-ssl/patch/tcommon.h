/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __TCOMMON_H__
#define __TCOMMON_H__

#include <stdlib.h>
#include <sgx_trts.h>
#include "sgx_tsgxssl_t.h"
#include "errno.h"

#include "tdefines.h"
#include "tSgxSSL_api.h"

#define SGX_SSL_SUCCESS 0

//#define DO_SGX_LOG
#define DO_SGX_WARN

#define SGX_ERROR(...) sgx_print("TERROR: " __VA_ARGS__);

#ifdef DO_SGX_WARN
#define SGX_WARNING(...) sgx_print("TWARNING: " __VA_ARGS__);
#else
#define SGX_WARNING(...)
#endif

#ifdef DO_SGX_LOG
#define SGX_LOG(...) sgx_print("TLOG: " __VA_ARGS__);
#else
#define SGX_LOG(...)
#endif

#define SGX_EXIT(err) \
{ \
	abort(); \
}


#ifdef DO_SGX_LOG
#define FSTART SGX_LOG("Enter %s\n", __FUNCTION__)
#define FEND SGX_LOG("Exit from %s\n", __FUNCTION__)
#else
#define FSTART
#define FEND
#endif

#define SET_NO_ERRNO	0
#define SET_ERRNO		1

#define ERROR_NOT_SUPPORTED		50L

#define SGX_REPORT_ERR(set_err) \
{ \
	if (set_err == SET_ERRNO) { \
		SGX_WARNING("%s(%d) - %s, this function is not supported! Setting errno to EINVAL...\n", __FILE__, __LINE__, __FUNCTION__); \
		errno = EINVAL; \
	} \
	else { \
		SGX_WARNING("%s(%d) - %s, this function is not supported! errno is not set ...\n", __FILE__, __LINE__, __FUNCTION__); \
	} \
}

#define SGX_UNSUPPORTED_FUNCTION	SGX_REPORT_ERR

#ifdef  __cplusplus
extern "C" {
#endif

extern UnreachableCodePolicy_t s_unreach_code_policy;

int sgx_print(const char *fmt, ...);

#ifdef  __cplusplus
}
#endif

#define SGX_UNREACHABLE_CODE(set_err) \
{ \
	if (s_unreach_code_policy == UNREACH_CODE_ABORT_ENCLAVE) { \
		SGX_ERROR("%s(%d) - %s, internal error! aborting...\n", __FILE__, __LINE__, __FUNCTION__); \
		SGX_EXIT(-1); \
	}\
	else { \
		SGX_REPORT_ERR(set_err); \
	} \
}

#endif // __TCOMMON_H__
