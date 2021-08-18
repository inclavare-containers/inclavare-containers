/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef QUOTE_VERIFICATION_H_
#define QUOTE_VERIFICATION_H_

#include <stdint.h>
#include <sgx_qve_header.h>

/** @struct sgxioc_ver_dcap_quote_arg_t
   *  A structure for DCAP quote verification
   *
   *  @var quote_bufer
   *    A pointer to the buffer storing the input quote.
   *  @var quote_size
   *    The size of the input quote.
   *  @var collateral_expiration_status
   *    A pointer to the value that stores the verification collateral
   *    expiration status. It is used by libos as a parameter to
   *    sgx_qv_verify_quote.
   *   @var supplemental_data_size
   *    The size of the buffer to store supplemental data.
   *   @var supplemental_data
   *    The pointer to the buffer to store the supplemental data.
*/
typedef struct {
	const uint8_t *quote_buf;
	uint32_t quote_size;
	uint32_t *collateral_expiration_status;
	sgx_ql_qv_result_t *quote_verification_result;
	uint32_t supplemental_data_size;
	uint8_t *supplemental_data;
} sgxioc_ver_dcap_quote_arg_t;

#define SGXIOC_GET_DCAP_SUPPLEMENTAL_SIZE _IOR('s', 9, uint32_t)
#define SGXIOC_VER_DCAP_QUOTE		  _IOWR('s', 10, sgxioc_ver_dcap_quote_arg_t)

#endif /* QUOTE_VERIFICATION_H_ */
