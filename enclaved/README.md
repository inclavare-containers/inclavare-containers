# Enclaved

## Introduction

Enclaved is a coordinator which creates a m-TLS(Mutal Transport Layer Security) connection between stub enclave and 
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

* Server(enclaved.wolfssl)

```bash

cd ${ROOT_DIR}/enclaved/
make -f Makefile.wolfssl

```

* Client

```bash

cd ${ROOT_DIR}/ra-tls/

```

#### Run

* Server

```bash

export SPID=<YOUR_SPID>
export EPID_SUBSCRIPTION_KEY=<YOUR_SUBSCRIPTION_KEY>
export QUOTE_TYPE=SGX_UNLINKABLE_SIGNATURE (or SGX_LINKABLE_SIGNATURE)

${ROOT_DIR}/enclaved/bin/enclaved.wolfssl

```

* Client: 

```bash

${ROOT_DIR}/ra-tls/elv/elv echo helloworld

```

### Base On Rust-sgx-sdk (DEPRECATED)

#### Build

```bash

cd ${ROOT_DIR}/enclaved/
make

```

#### Run

```

export SPID=<YOUR_SPID>
export EPID_SUBSCRIPTION_KEY=<YOUR_SUBSCRIPTION_KEY>
export QUOTE_TYPE=SGX_UNLINKABLE_SIGNATURE (or SGX_LINKABLE_SIGNATURE)

# Run server
${ROOT_DIR}/enclaved/bin/enclaved --server

# Run client
${ROOT_DIR}/enclaved/bin/enclaved --client

```
