/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef QUOTE_GENERATION_H_
#define QUOTE_GENERATION_H_

#include <stdint.h>
#include <sgx_ql_quote.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>

/** @struct sgxioc_gen_dcap_quote_arg_t
   *  A structure for DCAP quote generation
   *
   *  @var report_data
   *    The input report data to be included in the quote.
   *  @var quote_len
   *    A value-result argument: the caller must initialize it to contain the
   *    size (in bytes) of the buffer pointed to by quote_buf; on return it
   *    will contain the actual size of the output quote.
   *  @var quote_buf
   *    A pointer to the buffer to store the output quote.
*/
typedef struct {
	sgx_report_data_t *report_data;
	uint32_t *quote_len;
	uint8_t *quote_buf;
} sgxioc_gen_dcap_quote_arg_t;

typedef struct {
	const sgx_target_info_t *target_info; // input (optinal)
	const sgx_report_data_t *report_data; // input (optional)
	sgx_report_t *report; // output
} sgxioc_create_report_arg_t;

#define SGXIOC_GET_DCAP_QUOTE_SIZE _IOR('s', 7, uint32_t)
#define SGXIOC_GEN_DCAP_QUOTE	   _IOWR('s', 8, sgxioc_gen_dcap_quote_arg_t)
#define SGXIOC_CREATE_REPORT	   _IOWR('s', 4, sgxioc_create_report_arg_t)

int generate_quote(int sgx_fd, sgxioc_gen_dcap_quote_arg_t *gen_quote_arg);

#endif //QUOTE_GENERATION_H_
