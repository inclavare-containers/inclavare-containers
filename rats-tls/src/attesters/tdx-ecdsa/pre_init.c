/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <internal/cpu.h>
#include <rats-tls/attester.h>
#include <rats-tls/log.h>

enclave_attester_err_t tdx_ecdsa_attester_pre_init(void)
{
    RTLS_DEBUG("called\n");

    if (!is_in_tdguest()) {
        RTLS_ERR("tdx attester must run in tdx guest.\n");
        return ENCLAVE_ATTESTER_ERR_CPU_UNSUPPORTED;
    }

    RTLS_DEBUG("attester is running in tdx guest.\n");

    return ENCLAVE_ATTESTER_ERR_NONE;
}
