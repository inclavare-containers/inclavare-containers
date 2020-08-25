/* App.h
*
* Copyright (C) 2006-2016 wolfSSL Inc.
*
* This file is part of wolfSSL.
*
* wolfSSL is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* wolfSSL is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/

#ifndef STUB_ENCLAVE_H
#define STUB_ENCLAVE_H

#include "sgx_urts.h"	/* Manages Enclave */
#include <sys/types.h>	/* for send/recv */
#include <sys/socket.h>	/* for send/recv */

#include "Wolfssl_Enclave_u.h"	/* contains untrusted wrapper functions used to call enclave functions */

#define BENCH_RSA
#define ENCLAVE_FILENAME "Wolfssl_Enclave.signed.so"

enum BenchmarkBounds {
	/* these numbers are lower then default wolfSSL one to collect benchmark values faster for GUI */
	numBlocks = 10, /* how many megs to test */
	ntimes = 30 /* how many itteration to run RSA decrypt/encrypt */
};

#define PAL_DEBUG(fmt, ...) \
	fprintf(stderr, "[DEBUG] stub-enclave: " fmt " (line %d, file %s)\n", ##__VA_ARGS__, __LINE__, __FILE__)
#define PAL_INFO(fmt, ...) \
	fprintf(stderr, "[INFO] stub-enclave: " fmt " (line %d, file %s)\n", ##__VA_ARGS__, __LINE__, __FILE__)
#define PAL_WARN(fmt, ...) \
	fprintf(stderr, "[WARM] stub-enclave: " fmt " (line %d, file %s)\n", ##__VA_ARGS__, __LINE__, __FILE__)
#define PAL_ERROR(fmt, ...) \
	fprintf(stderr, "[ERROR] stub-enclave: " fmt " (line %d, file %s)\n", ##__VA_ARGS__, __LINE__, __FILE__)

#endif	/* STUB_ENCLAVE_H */
