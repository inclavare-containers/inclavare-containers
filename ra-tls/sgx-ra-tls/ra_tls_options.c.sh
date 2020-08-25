#!/bin/bash

# set -x

if [[ -z "$ECDSA_SUBSCRIPTION_KEY" ]] && ( [[ -z "$SPID" ]] || [[ -z "$EPID_SUBSCRIPTION_KEY" ]] ); then
    echo "//Either SPID and EPID_SUBSCRIPTION_KEY or ECDSA_SUBSCRIPTION_KEY is required!"
fi

if ( [[ ! -z "$SPID" ]] && [[ -z "$EPID_SUBSCRIPTION_KEY" ]] ) || \
   ( [[ -z "$SPID" ]] && [[ ! -z "$EPID_SUBSCRIPTION_KEY" ]] ); then
    echo "//For EPID, Both SPID and EPID_SUBSCRIPTION_KEY must be set!"
fi

if ( [[ "$QUOTE_TYPE" != "SGX_LINKABLE_SIGNATURE" ]] ) && \
   ( [[ "$QUOTE_TYPE" != "SGX_UNLINKABLE_SIGNATURE" ]] ); then
    echo "//QUOTE_TYPE must be one of SGX_UNLINKABLE_SIGNATURE or SGX_LINKABLE_SIGNATURE"
fi

SPID_BYTE_ARRAY=$(echo $SPID | python -c 'import sys ; s = sys.stdin.readline().strip(); print("".join(["0x"+s[2*i:2*i+2]+"," for i in range(len(s)/2)]))')

cat <<HEREDOC
#include "ra-attester.h"

struct ra_tls_options my_ra_tls_options = {
    // SPID format is 32 hex-character string, e.g., 0123456789abcdef0123456789abcdef
    .spid = {{$SPID_BYTE_ARRAY}},
    .quote_type = SGX_UNLINKABLE_SIGNATURE,
    .ias_server = "api.trustedservices.intel.com/sgx/dev",
    // EPID_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = "$EPID_SUBSCRIPTION_KEY"
};

struct ecdsa_ra_tls_options my_ecdsa_ra_tls_options = {
    // ECDSA_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = "$ECDSA_SUBSCRIPTION_KEY"
};
HEREDOC
