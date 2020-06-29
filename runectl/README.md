# runectl
## Introduction
`runectl` is a command line tool for inclavare-containers.
- Given the signature file of an Enclave, `runectl gen-token` command can generate the corresponding token file from aesmd service.
- `runectl gen-qe-target-info` command can generate Quoting Enclave's target information file from aesm service.
- Given the report file of an Enclave, `runectl gen-quote` command can generate quote file from aesm service.

## Install Intel `aesmd` service
### Hardware requirements
- Install [Intel SGX driver for Linux](https://github.com/intel/linux-sgx-driver#build-and-install-the-intelr-sgx-driver), required by [Intel SGX SDK && PSW](https://github.com/intel/linux-sgx).

### Software requirements
- Build [Intel(R) SGX SDK and Intel(R) SGX PSW](https://github.com/intel/linux-sgx#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package) to install the `aesmd` service.

## Dependency
- golang 1.14 or above.
- protoc-gen-go v1.3.5
  `go get github.com/golang/protobuf/protoc-gen-go@v1.3.5`.

## Build
```
$ make
```

## Install
```
$ sudo make install
```

## Uninstall
```
$ sudo make uninstall
```

## Test 
### `runectl gen-token` test
```
$ make test
```

The expected output is as following:
```
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
