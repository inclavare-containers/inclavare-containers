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

#include <stdio.h>
#include <string.h>
#include "tcommon.h"
#include "sgx_tsgxssl_t.h"
#include "tSgxSSL_api.h"
#include "tsgxsslio.h"

extern PRINT_TO_STDOUT_STDERR_CB s_print_cb;

extern "C" {

int sgx_print(const char *format, ...)
{
	if (s_print_cb != NULL) {
		va_list vl;
		va_start(vl, format);
		int res = s_print_cb(STREAM_STDOUT, format, vl);
		va_end(vl);

		return res;
	}

	return 0;
}

int print_with_cb(void* fp, const char* fmt, __va_list vl)
{
    int res = -1;
    int stream = -1;

    if (fp == NULL || s_print_cb == NULL)
        return -1;

    if (fp == stdout)
        stream = STREAM_STDOUT;
    else if (fp == stderr)
        stream = STREAM_STDERR;
    else
        return res;

    res = s_print_cb((Stream_t)stream, fmt, vl);

    return res;
}

void *sgxssl_fopen(const char *filename, const char *mode)
{
    uint64_t ret = 0;
    int res;

    if (filename == NULL || mode == NULL)
        return NULL;

    res = ocall_sgxssl_fopen(&ret, filename, strlen(filename) + 1, mode, strlen(mode) + 1);
    if (res != SGX_SSL_SUCCESS)
        return NULL;

    return (void *)ret;
}

int sgxssl_fclose(void *fp)
{
    int ret = -1;
    int res;

    if (fp == NULL)
        return -1;

    res = ocall_sgxssl_fclose(&ret, (uint64_t)fp);
    if (res != SGX_SSL_SUCCESS)
        return -1;

    return ret;
}

int sgxssl_ferror(void *fp)
{
    int ret = -1;
    int res;

    if (fp == NULL)
        return -1;

    res = ocall_sgxssl_ferror(&ret, (uint64_t)fp);
    if (res != SGX_SSL_SUCCESS)
       return -1;

    return ret;
}

int sgxssl_feof(void *fp)
{
    int ret = 0;
    int res;

    if (fp == NULL)
       return 0;

    res = ocall_sgxssl_feof(&ret, (uint64_t)fp);
    if (res != SGX_SSL_SUCCESS)
       return 0;

    return ret;
}

int sgxssl_fflush(void *fp)
{
    int ret = -1;
    int res;

    if (fp == NULL)
        return -1;

    res = ocall_sgxssl_fflush(&ret, (uint64_t)fp);
    if (res != SGX_SSL_SUCCESS)
        return -1;

    return ret;
}

long sgxssl_ftell(void *fp)
{
    long ret = -1;
    int res;

    if (fp == NULL)
       return -1;

    res = ocall_sgxssl_ftell(&ret, (uint64_t)fp);
    if (res != SGX_SSL_SUCCESS)
        return -1;

    return ret;
}

int sgxssl_fseek(void *fp, long offset, int origin)
{
    int ret = -1;
    int res;

    if (fp == NULL)
        return -1;

    res = ocall_sgxssl_fseek(&ret, (uint64_t)fp, offset, origin);
    if (res != SGX_SSL_SUCCESS)
        return -1;

    return ret;
}


int sgxssl_fprintf(void *fp, const char *format, ...)
{
    if (s_print_cb != NULL) {
        va_list vl;
        va_start(vl, format);
        int res = print_with_cb(fp, format, vl);
        va_end(vl);

       return res;
     }

    return -1;
}

int sgxssl_vfprintf(void *fp, const char *format, va_list vl)
{
    if (s_print_cb != NULL) {
        int res = print_with_cb(fp, format, vl);
        return res;
    }

    return -1;
}

size_t sgxssl_fread(void *dest, size_t element_size, size_t cnt, void *fp)
{
    size_t ret = 0;
    int res;

    if (fp == NULL || dest == NULL || element_size == 0 || cnt == 0)
        return 0;

    if (element_size > (SIZE_MAX - 1) / cnt + 1)
        return 0;

    res = ocall_sgxssl_fread(&ret, dest, element_size * cnt, element_size, cnt, (uint64_t)fp);
    if (res != SGX_SSL_SUCCESS)
        return 0;

    return ret;
}

size_t sgxssl_fwrite(const void *src, size_t element_size, size_t cnt, void *fp)
{
    size_t ret = 0;
    int res;

    if (fp == NULL || src == NULL || element_size == 0 || cnt == 0)
        return 0;

    if (element_size > (SIZE_MAX - 1) / cnt + 1)
        return 0;

    res = ocall_sgxssl_fwrite(&ret, src, element_size * cnt, element_size, cnt, (uint64_t)fp);
    if (res != SGX_SSL_SUCCESS)
        return 0;

    return ret;
}

char *sgxssl_fgets(char *dest, int max_cnt, void *fp)
{
        int ret = -1;
        int res;

        if (fp == NULL || dest == NULL || max_cnt <= 0)
                return NULL;

        res = ocall_sgxssl_fgets(&ret, dest, max_cnt, (uint64_t)fp);
        if (res != SGX_SSL_SUCCESS || ret < 0)
                return NULL;

        return dest;
}

int sgxssl_fputs(const char *src, void *fp)
{
        int ret = -1;
        int res;

        if (fp == NULL || src == NULL)
                return -1;

        res = ocall_sgxssl_fputs(&ret, src, strlen(src) + 1, (uint64_t)fp);
        if (res != SGX_SSL_SUCCESS || ret < 0)
                return -1;

        return ret;
}

}
