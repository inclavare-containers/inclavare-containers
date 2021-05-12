# Background

Both untrusted QVL and trusted QvE fails to verify the quote generated
by the pre-product SGX platform (SBX). This patch resolves this issue.

The root cause is due to the fact that the built-in Intel Root CA
certificate used to authenticate the root ca certificate in PCK
certificate chain of the quote is for product platform, and is hardcoded
in the official binaries of untrusted QVL and trusted QvE.

This means the user cannot use QVL and QvE to verify the quote with the
PCK certificate provided by Intel provisioning service for SBX platforms.

To confirm whether you are using a SBX platform, run the following command:

```shell
strings /sys/firmware/efi/efivars/SgxRegistrationConfiguration-18b3bc81-e210-42b9-9ec8-2c5a7d4d89b6  | grep intel.com
```

If the result is `https://sbx.api.trustedservices.intel.com:443`, please
access to `https://sbx.api.portal.trustedservices.intel.com/provisioning-certification`
to subscribe the primary key for SBX platform.

# Solution

The modified QVL/QVE applied to this patch at least allows the user to
verify the quote rooting to Intel Root CA certificate for SBX platforms.
In order to minimize the influence, it is recommended to run applications
(taken QuoteVerificationSample as example) using the modified QVL/QVE
(libsgx_dcap_quoteverify.so.1/libsgx_qve.signed.so) with the following
ethod:

```shell
# re-configure Intel PCCS with SBX support
sudo sed -i 's/api.trustedservices.intel.com/sbx.api.trustedservices.intel.com/' /opt/intel/sgx-dcap-pccs/config/default.json
# replace ApiKey field with the subscribed SBX primary key
# restart Intel PCCS service
sudo systemctl restart pccs
# apply the patch
cd $PATH_TO_SGX_SDK_SOURCE/external/dcap_source
git am $PATH_TO_INCLAVARE/hack/use-sbx-platform/0001-QVL-QVE-allow-to-use-SBX-platform.patch
source /opt/intel/sgxsdk/environment
# generate quote
cd $PATH_TO_SGX_SDK_SOURCE/external/dcap_source/SampleCode/QuoteGenerationSample
make clean && make
SGX_AESM_ADDR=1 ./app
# rebuild QVL/QVE with SBX support
cd ../../QuoteVerification
make clean
USE_SBX_PLATFORM=1 make
# replace with modified QVL/QVE
[ -d /usr/lib/x86_64-linux-gnu ] &&
  sudo cp -f dcap_quoteverify/linux/libsgx_dcap_quoteverify.so.1 /usr/lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so.1.* ||
  sudo cp -f dcap_quoteverify/linux/libsgx_dcap_quoteverify.so.1 /usr/lib64/libsgx_dcap_quoteverify.so.1.*
sudo ldconfig
[ -d /usr/lib/x86_64-linux-gnu ] &&
  sudo cp -f QvE/libsgx_qve.signed.so /usr/lib/x86_64-linux-gnu ||
  sudo cp -f QvE/libsgx_qve.signed.so /usr/lib64
# replace the original
make clean -C dcap_tvl
USE_SBX_PLATFORM=1 make -C dcap_tvl
sudo cp -f dcap_tvl/libsgx_dcap_tvl.a /opt/intel/sgxsdk/lib64
# verify quote
cd ../SampleCode/QuoteVerificationSample
make clean && make
./app
```

Note: QVE (libsgx_qve.signed.so) is signed by the testing key. So don't use this modified QVE in product.

# Validation

You will get the following result:

```
Info: ECDSA quote path: ../QuoteGenerationSample/quote.dat

Trusted quote verification:
	Info: get target info successfully returned.
	Info: sgx_qv_set_enclave_load_policy successfully returned.
	Info: sgx_qv_get_quote_supplemental_data_size successfully returned.
	Info: App: sgx_qv_verify_quote successfully returned.
	Info: Ecall: Verify QvE report and identity successfully returned.
	Info: App: Verification completed successfully.

===========================================

Untrusted quote verification:
	Info: sgx_qv_get_quote_supplemental_data_size successfully returned.
	Info: App: sgx_qv_verify_quote successfully returned.
	Info: App: Verification completed successfully.
```
