# sgx-tools
## Introduction

`sgx-tools` is a command line tool based on inclavare-containers. `sgx-tools` can serve three kinds of quote types:
- `epidUnlinkable`: [epid for unlinkable](https://api.portal.trustedservices.intel.com/EPID-attestation)
- `epidLinkable`: [epid for linkable](https://api.portal.trustedservices.intel.com/EPID-attestation)
- `ecdsa`: [ECDSA](https://github.com/intel/linux-sgx#ecdsa-attestation). **Note `sgx-tools` currently only support `gen-qe-target-info` and `gen-quote` commands**.

### Commands

`sgx-tools` supports this following commands:
- Given the signature file of an Enclave, `sgx-tools gen-token` command can generate the corresponding token file from aesmd service.
- `sgx-tools gen-qe-target-info` command can generate Quoting Enclave's target information file from aesm service.
- Given the report file of an Enclave, `sgx-tools gen-quote` command can generate quote file from aesm service for the `ecdsa` quote type. 
	- As for the `epidUnlinkable` and `epidLinkable` quote types, a registered `SPID` of [IAS](https://api.portal.trustedservices.intel.com/EPID-attestation) also needs to be provided for generating the quote file.
	- To get the report file, you can use `rune attest` command to get you local report and save it in the report file.
- Given the quote file of an Enclave, `sgx-tools verify-quote` command can verify quote
	- As for the `ecdsa` quote type, `sgx-tools verify-quote` command can verify quote with the help of [PCCS](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/pccs).
	- As for the `epidUnlinkable` and `epidLinkable` quote types, a registered `SPID` and `Subscription Key` of [IAS](https://api.portal.trustedservices.intel.com/EPID-attestation) also need to be provided `sgx-tools verify-quote` command to verify quote with the help of IAS.

## Install Intel `aesmd` service
### Hardware requirements

- Install Intel SGX driver for Linux by following [Intel SGX Installation Guide](https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Installation_Guide_Linux_2.9.1_Open_Source.pdf), required by [Intel SGX SDK && PSW](https://github.com/intel/linux-sgx).

### Software requirements

- Build Intel(R) SGX SDK and Intel(R) SGX PSW by following [Intel SGX Installation Guide](https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Installation_Guide_Linux_2.9.1_Open_Source.pdf) to install the `aesmd` service.

## Dependency

- golang 1.14 or above.
- libsgx-dcap-quote-verify-dev (Ubuntu) from [official Intel SGX DCAP release page](https://01.org/intel-software-guard-extensions/downloads).
- libsgx-aesm-quote-ex-plugin from [official Intel SGX Linux release page](https://01.org/intel-software-guard-extensions/downloads).

## Build

```shell
$ make
```

## Install

```shell
$ sudo make install
```

## Uninstall

```shell
$ sudo make uninstall
```

## Test 
### `sgx-tools gen-token` test

```shell
$ make test
```

The expected output is as following:

```shell
SIGSTRUCT:
  Enclave Vendor:             0x00000000
  Enclave Build Date:               2019-10-7
  Software Defined:           0x00000000
  ISV assigned Product Family ID:   0x00000000000000000000000000000000
  ISV assigned Produdct ID:         0x0000
  ISV assigned Extended Product ID: 0x00000000000000000000000000000000
  ISV assigned SVN:                 0
  Enclave Attributes:               0x06000000000000000300000000000000
  Enclave Attributes Mask:          0x06000000000000000300000000000000
  Enclave Misc Select:              0x00000000
  Enclave Misc Mask:                0x00000000
  Enclave Hash:                     0x7470ffc919e823e0f6a9592e05fe523b228b491865aadf0cfe7ce5ddd31412b5
  Modulus:                          0x190e2d49ccda2097efa00061aa028d1eb1633a602ae924f609c5bfec2ba9a3d9...
  Exponent:                         3
  Signature:                        0x4b159a3594b24177fbdb16b21e60194275b58d5d8badf6b444ee72ddfc015913...
  Q1:                               0x2954df0757eff2f1653b80e88d99246edb33ec115f7365cd340658903363b0e7...
  Q2:                               0x19d4f5c51a56567286027b4f9f619b780fa258c90bad9a32db85f77a107b15eb...
EINITTOKEN:
  Valid:                                    1
  Enclave Attributes:                       0x06000000000000000300000000000000
  Enclave Hash:                             0x7470ffc919e823e0f6a9592e05fe523b228b491865aadf0cfe7ce5ddd31412b5
  Enclave Signer:                           0x5bde1ae94215c4ad6c6c4430ba880fd841b2184637ac907a44b832b1b226bbd4
  Launch Enclave's CPU SVN :                0x050e0204ff0200000000000000000000
  Launch Enclave's ISV assigned Product ID: 0x0020
  Launch Enclave's ISV assigned SVN:        3
  Launch Enclave's Masked Misc Select:      0x00000000
  Launch Enclave's Masked Attributes:       0x21000000000000000000000000000000
  Key ID:                                   0x0bbcfaf50b2baf7ad7b3f6b25621bb0b241b7e3c517a77305711f0f39f8c3c47
  MAC:                                      0x135de69cd3bcbaa09264c7a5b985d0bf
token file test/hello-world.token saved
```

## Third Party Dependencies

### Direct dependencies

| Name | Repo URL | Licenses |
| ---- | -------- | -------- |
| cli | github.com/urfave/cli | MIT |
| blackfriday | github.com/russross/blackfriday/v2 | BSD-2-Clause|
| logrus | github.com/sirupsen/logrus | MIT |
| libenclave | github.com/inclavare-containers/rune/libenclave | Apache-2.0 |
| proto | github.com/golang/protobuf/proto | BSD-3-Clause |
| protobuf | google.golang.org/protobuf | BSD-3-Clause |
| sys | golang.org/x/sys | BSD-3-Clause |
| md2man | github.com/cpuguy83/go-md2man/v2/md2man | MIT|
| sanitized_anchor_name | github.com/shurcooL/sanitized_anchor_name | MIT |
| restruct | github.com/go-restruct/restruct | ISC |
| errors | github.com/pkg/errors | BSD-2-Clause |
| DCAP | https://github.com/intel/SGXDataCenterAttestationPrimitives | BSD |
