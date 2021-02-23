# Inclavared

## Introduction

Inclavared is a coordinator which creates a m-TLS(Mutal Transport Layer Security) connection between stub enclave and 
other enclaves with remote attestation (aka "[RA-TLS](https://raw.githubusercontent.com/cloud-security-research/sgx-ra-tls/master/whitepaper.pdf)").

Currently, we integrate two implementations for ra-tls based on [sgx-ra-tls(wolfssl)](https://github.com/cloud-security-research/sgx-ra-tls) and  [mutual-ra(rust-sgx-sdk)-DEPRECATED](https://github.com/apache/incubator-teaclave-sgx-sdk/tree/master/samplecode/mutual-ra).

## Design

![kubernetes-attestation](docs/images/Kuberntes-Cluster-Attestation-Architecture.png)

## Installation

TODO

## Build Source Code

### Requirements
* rust-lang

### Setup Environment

```bash
cargo install protobuf
cargo install bindgen

# Linux(Centos/RHEL)
yum install -y clang-libs  clang-devel

# MacOS
brew install clang

git clone https://github.com/alibaba/inclavare-containers.git
cd inclavare-containers/
export ROOT_DIR=`pwd`

```

### Based On WolfSSL

#### Build

* Set EPID or DCAP environment variable

EPID environment variable:

``` bash
export SPID=<YOUR_SPID>
export EPID_SUBSCRIPTION_KEY=<YOUR_SUBSCRIPTION_KEY>
export QUOTE_TYPE=SGX_UNLINKABLE_SIGNATURE (or SGX_LINKABLE_SIGNATURE)
```

DCAP environment variable:

``` bash
export SGX_DCAP=<DCAP_REPO_DIRECTORY>
```

* inclavared (inclavared.wolfssl)

```bash
cd ${ROOT_DIR}/inclavared/
make -f Makefile.wolfssl
```

* inclavared (inclavared.wolfssl) for DCAP

```bash
cd ${ROOT_DIR}/inclavared/
make -f Makefile.wolfssl ECDSA=1
```

* inclavared (inclavared.wolfssl) for LA_REPORT

```bash
cd ${ROOT_DIR}/inclavared/
make -f Makefile.wolfssl LA=1
```

#### Run

* Run as server

```bash
${ROOT_DIR}/inclavared/bin/inclavared.wolfssl --listen <unixsock>
```

* Xfer data between client and server

recv data from unixsock1 and send to unixsock2, and recv data from unixsock2 and send to unixsock1

```bash
${ROOT_DIR}/inclavared/bin/inclavared.wolfssl --listen <unixsock1> --xfer <unixsock2>
```

* Run as client

```bash
${ROOT_DIR}/inclavared/bin/inclavared.wolfssl --connect <unixsock>
```

### Base On Rust-sgx-sdk (DEPRECATED)

#### Build

```bash

cd ${ROOT_DIR}/inclavared/
make

```

#### Run

```

export SPID=<YOUR_SPID>
export EPID_SUBSCRIPTION_KEY=<YOUR_SUBSCRIPTION_KEY>
export QUOTE_TYPE=SGX_UNLINKABLE_SIGNATURE (or SGX_LINKABLE_SIGNATURE)

# Run server
${ROOT_DIR}/inclavared/bin/inclavared --server

# Run client
${ROOT_DIR}/inclavared/bin/inclavared --client

```
