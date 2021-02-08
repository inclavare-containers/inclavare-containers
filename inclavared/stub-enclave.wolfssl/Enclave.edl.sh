#!/bin/bash

# set -x

if ( [[ ! -z "$ECDSA" ]] ); then
cat > stub-enclave.wolfssl/Enclave.edl <<EOF
enclave {
    from "sgx_backtrace.edl" import *;
    from "sgx_tstd.edl" import *;
    from "sgx_stdio.edl" import *;
    from "sgx_fs.edl" import *;
    from "sgx_net.edl" import *;
    from "sgx_time.edl" import *;
    from "sgx_tstdc.edl" import *;
    from "sgx_env.edl" import *;

    from "wolfssl.edl" import *;

    include "ra.h"
    include "ra-attester.h"
    include "sgx_report.h"

    trusted {
    };

    untrusted {
        /* define OCALLs here. */
	    void ocall_collect_attestation_evidence([in] sgx_report_t* p_report,
						[out] ecdsa_attestation_evidence_t* evidence);
	    void ocall_ratls_get_target_info([out] sgx_target_info_t *qe_target_info);
    };
};
EOF
fi

if ( [[ -z "$ECDSA" ]] ); then
cat > stub-enclave.wolfssl/Enclave.edl <<EOF
enclave {
    from "sgx_backtrace.edl" import *;
    from "sgx_tstd.edl" import *;
    from "sgx_stdio.edl" import *;
    from "sgx_fs.edl" import *;
    from "sgx_net.edl" import *;
    from "sgx_time.edl" import *;
    from "sgx_tstdc.edl" import *;
    from "sgx_env.edl" import *;

    from "wolfssl.edl" import *;

    include "ra.h"
    include "ra-attester.h"
    include "sgx_report.h"

    trusted {
    };

    untrusted {
        /* define OCALLs here. */
        void ocall_sgx_init_quote([out] sgx_target_info_t* target_info);
        void ocall_remote_attestation([in] sgx_report_t* report,
                                      [in] const struct ra_tls_options* opts,
                                      [out] attestation_verification_report_t* attn_report
                                      );
    };
};
EOF
fi
