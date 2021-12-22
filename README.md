# Building

## Build Requirements

- git
- make
- autoconf
- libtool
- gcc
- g++ (ubuntu 18.04) or gcc-c++ (centos 8.2)
- SGX driver, Intel SGX SDK & PSW: Please refer to this [guide](https://download.01.org/intel-sgx/sgx-linux/2.14/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) to install.
- [SGX DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives): please download and install the packages from this [page](https://download.01.org/intel-sgx/sgx-dcap/#version#linux/distro).
  - centos 8.2: `libsgx-dcap-quote-verify-devel`, `libsgx-dcap-ql-devel`, `libsgx-uae-service`
  - ubuntu 18.04: `libsgx-dcap-quote-verify-dev`, `libsgx-dcap-ql-dev`, `libsgx-uae-service`
- For TDX, please see the README in TDX MVP Stack. You need to download the packages and following TDX_E2E_attestation_software_stack_Installation_README-dcap-2021XXXX.txt to do step 2 & step 3 to setup build and dependence libraries.

## Build and Install

Please follow the command to build RATS TLS from the latested source code on your system.

1. Download the latest source code of RATS TLS

```shell
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
git clone https://github.com/alibaba/inclavare-containers
```

2. Build and install RATS TLS

```shell
cd inclavare-containers/rats-tls
cmake -DBUILD_SAMPLES=on -H. -Bbuild
make -C build install
```

`{rats-tls-server,rats-tls-client}` will be installed to `/usr/share/rats-tls/samples/{rats-tls-server,rats-tls-client}` on your system. All instances are placed in `/opt/rats-tls/lib`.

If you want to build instances related to sgx(sgx\_ecdsa, sgx\_ecdsa\_qve, sgx\_la), please type the following command.

```shell
cmake -DRATS_TLS_BUILD_MODE="sgx" -DBUILD_SAMPLES=on -H. -Bbuild
make -C build install
```

If you want to run instances on libos occlum, please type the following command.

```shell
cmake -DRATS_TLS_BUILD_MODE="occlum" -DBUILD_SAMPLES=on -H. -Bbuild
make -C build install
```

If you want to run TDX instances, please type the following command.
```shell
cmake -DRATS_TLS_BUILD_MODE="tdx" -DBUILD_SAMPLES=on -H. -Bbuild
make -C build install
```

Note that [SGX LVI mitigation](https://software.intel.com/security-software-guidance/advisory-guidance/load-value-injection) is enabled by default. You can set macro `SGX_LVI_MITIGATION` to `0` to disable SGX LVI mitigation.

# RUN

Right now, RATS TLS supports the following instance types:

| Priority | Tls Wrapper instances |     Attester instances     |     Verifier instances     | Crypto Wrapper Instance |
| -------- | --------------------- | -------------------------- | -------------------------- | ----------------------- |
| low      | nulltls               | nullattester               | nullverifier               | nullcrypto              |
| Medium   | openssl               | sgx\_la                    | sgx\_la                    | openssl                 |
| High     | openssl               | tdx\_ecdsa                 | tdx\_ecdsa                 | openssl                 |
| Higher   | openssl               | sgx\_ecdsa                 | sgx\_ecdsa sgx\_ecdsa\_qve | openssl                 |

By default, RATS TLS will select the **highest priority** instance to use.

## Run RATS TLS server

```
cd /usr/share/rats-tls/samples
./rats-tls-server
```

## Run RATS TLS client
```
cd /usr/share/rats-tls/samples
./rats-tls-client
```

**Notice: special prerequisites for TDX remote attestation in bios configuration and hardware capability.**

Check msr 0x503, return value must be 0:
```
sudo rdmsr 0x503s
```

## Specify the instance type

The options of rats-tls-server are as followed:

```shell
OPTIONS:
   --attester/-a value   set the type of quote attester
   --verifier/-v value   set the type of quote verifier
   --tls/-t value        set the type of tls wrapper
   --crypto/-c value     set the type of crypto wrapper
   --mutual/-m           set to enable mutual attestation
   --log-level/-l        set the log level
   --ip/-i               set the listening ip address
   --port/-p             set the listening tcp port
   --product-enclave/-P  set to enable product enclave
   --verdictd/-E         set to connect verdictd based on EAA protocol
```

You can set command line parameters to specify different configurations.

For example:

```shell
./rats-tls-server --tls openssl
./rats-tls-server --attester sgx_ecdsa
./rats-tls-server --attester sgx_ecdsa_qve
./rats-tls-server --attester sgx_la
./rats-tls-server --attester tdx_ecdsa
./rats-tls-server --crypto openssl
```

RATS TLS's log level can be set through `-l` option with 6 levels: `off`, `fatal`, `error`, `warn`, `info`, and `debug`. The default level is `error`. The most verbose level is `debug`.

For example:

```
./rats-tls-server -l debug
```

RATS TLS server binds `127.0.0.1:1234` by default. You can use `-i` and `-p` options to set custom configuration.

```shell
./rats-tls-server -i [ip_addr] -p [port]
```

## Mutual attestation

You can use `-m` option to enable mutual attestation.

```shell
./rats-tls-server -m
./rats-tls-client -m
```

## Enable bootstrap debugging

In the early bootstrap of rats-tls, the debug message is mute by default. In order to enable it, please explicitly set the environment variable `RATS_TLS_GLOBAL_LOG_LEVEL=<log_level>`, where \<log_level\> is same as the values of the option `-l`.

# Deployment

## Occlum LibOS

Please refer to [this guide](docs/run_rats_tls_with_occlum.md) to run Rats Tls with [Occlum](https://github.com/occlum/occlum) and [rune](https://github.com/alibaba/inclavare-containers/tree/master/rune).

## Non-SGX Enviroment

In non-sgx enviroment, it's possible to show the error messages as below when running the command `./rats-tls-client --attester sgx_ecdsa`. According to Intel DCAP's implementation, when calling to sgx_qv_get_quote_supplemental_data_size(),
if the libsgx_urts library is present, it will try to load QvE firstly. If failed, the verification will be launched by QVL. So the error info can be ignored and have no impact on the final attestation result.

```
[load_qve ../sgx_dcap_quoteverify.cpp:209] Error, call sgx_create_enclave for QvE fail [load_qve], SGXError:2006.
[sgx_qv_get_quote_supplemental_data_size ../sgx_dcap_quoteverify.cpp:527] Error, failed to load QvE.
```

# Third Party Dependencies

Direct Dependencies

| Name | Repo URL | Licenses |
| :--: | :-------:   | :-------: |
| openssl | https://github.com/openssl/openssl | Apache |
| linux-sgx | https://github.com/intel/linux-sgx | BSD-3-clause |
| SGXDataCenterAttestationPrimitives | https://github.com/intel/SGXDataCenterAttestationPrimitives | BSD-3-clause |
| GNU C library | C library | GNU General Public License version 3 |
