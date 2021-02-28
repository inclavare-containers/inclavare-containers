# Background

Both untrusted QVL and trusted QvE fails to verify the quote generated
by the pre-product SGX platform (SBX). This patch resolves this issue.

The root cause is due to the fact that the built-in Intel Root CA
certificate used to authenticate the root ca certificate in PCK
certificate chain of the quote is for product platform, and is hardcoded
in the official binaries of untrusted QVL and trusted QvE.

This means the user cannot use QVL and QvE to verify the quote with the
PCK certificate provided by Intel provisioning service for SBX platforms.

# Solution

The modified QVL applied to this patch at least allows the user to
verify the quote rooting to Intel Root CA certificate for SBX platforms.
In order to minimize the influence, it is recommended to run applications
(taken QuoteVerificationSample as example) using the modified QVL
(libsgx_dcap_quoteverify.so.1) with the following method:

```shell
cd $PATH_TO_DCAP_SOURCE
git am $PATH_TO_INCLAVARE/hack/use-sbx-platform/0001-QVL-allow-to-use-SBX-platform.patch 
source /opt/intel/sgxsdk/environment
cd $PATH_TO_DCAP_SOURCE/SampleCode/QuoteGenerationSample
make clean && make
SGX_AESM_ADDR=1 ./app
cd $PATH_TO_DCAP_SOURCE/QuoteVerification/dcap_quoteverify/linux
make clean
USE_SBX_PLATFORM=1 make
cd ../../../SampleCode/QuoteVerificationSample
make clean
make
LD_LIBRARY_PATH=$PATH_TO_DCAP_SOURCE/QuoteVerification/dcap_quoteverify/linux:$LD_LIBRARY_PATH ./app
```

# Validation

You will get the following result:

```
===========================================

Untrusted quote verification:
[load_qve ../sgx_dcap_quoteverify.cpp:209] Error, call sgx_create_enclave for QvE fail [load_qve], SGXError:200f.
[sgx_qv_get_quote_supplemental_data_size ../sgx_dcap_quoteverify.cpp:527] Error, failed to load QvE.
        Info: sgx_qv_get_quote_supplemental_data_size successfully returned.
[load_qve ../sgx_dcap_quoteverify.cpp:209] Error, call sgx_create_enclave for QvE fail [load_qve], SGXError:200f.
[sgx_qv_get_quote_supplemental_data_size ../sgx_dcap_quoteverify.cpp:527] Error, failed to load QvE.
        Info: App: sgx_qv_verify_quote successfully returned.
        Info: App: Verification completed successfully.
```

Please ignore the error messages about loading QvE failure, which is
expected to retrieve the information of supplemental data from QvE.
