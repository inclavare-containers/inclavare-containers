# Configure SGX RA settings

## For EPID RA

``` shell
export SPID=<hex string>
export EPID_SUBSCRIPTION_KEY=<hex string>
export QUOTE_TYPE=<SGX_LINKABLE_SIGNATURE | SGX_UNLINKABLE_SIGNATURE>
```

## For DCAP RA

```shell
mkdir -p $PATH_TO_DCAP_SOURCE
cd $PATH_TO_DCAP_SOURCE
git clone https://github.com/intel/SGXDataCenterAttestationPrimitives/
export SGX_DCAP=$PATH_TO_DCAP_SOURCE/SGXDataCenterAttestationPrimitives
```

# Build

## For EPID RA

``` shell
sudo yum install -y glibc-static
cd $src/ra-tls
make
```

## For DCAP RA

Please refer to [this guide](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/README.md) to install DCAP.
Note: If your platform is pre-product SGX platform (SBX), please follow this guide to resolve the quote verification problem on SBX platforms: https://github.com/alibaba/inclavare-containers/blob/master/hack/use-sbx-platform/README.md.

```shell
cd $src/ra-tls
make ECDSA=1
```

## For Local Report Attestation

```shell
cd $src/ra-tls
make LA=1
```

# Run

``` shell
mkdir -p /run/rune
cd build/bin
./ra-tls-server run &
./elv echo
```

# Trouble shooting

## For EPID RA

### parse_response_header assertion

```
ra-tls-server: untrusted/ias-ra.c:153: parse_response_header: Assertion `sig_begin != ((void *)0)' failed.
./run.sh: line 5: 49050 Aborted                 ./ra-tls-server -s
```

This error is caused due to invalid SGX RA settings. Please configure SGX RA settings with valid values.

## FOR DACP RA

```
Untrusted quote verification:
[load_qve ../sgx_dcap_quoteverify.cpp:209] Error, call sgx_create_enclave for QvE fail [load_qve], SGXError:200f.
[sgx_qv_get_quote_supplemental_data_size ../sgx_dcap_quoteverify.cpp:527] Error, failed to load QvE.
        Info: sgx_qv_get_quote_supplemental_data_size successfully returned.
[load_qve ../sgx_dcap_quoteverify.cpp:209] Error, call sgx_create_enclave for QvE fail [load_qve], SGXError:200f.
[sgx_qv_get_quote_supplemental_data_size ../sgx_dcap_quoteverify.cpp:527] Error, failed to load QvE.
        Info: App: sgx_qv_verify_quote successfully returned.
        Info: App: Verification completed successfully.
```

Please ignore the error messages about loading QvE failure, which is expected to retrieve the information of supplemental data from QvE.
