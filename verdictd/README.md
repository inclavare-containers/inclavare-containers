# Verdictd

## Introduction

Verdictd is a server(as RATS shelterd) which creates an m-TLS(Mutal Transport Layer Security) connection with Attestation Agent via remote attestation (aka "[RA-TLS](https://raw.githubusercontent.com/cloud-security-research/sgx-ra-tls/master/whitepaper.pdf)").
Mainly functions:
- Handle "decryption" and "get KEK" requests from Attestation Agent, and response with corresponding results.
- Launch wrap/unwrap gRPC service which can be used by ocicrypto [containers/ocicrypto](https://github.com/containers/ocicrypt).

## Design

TODO

## Installation

TODO

## Build Source Code

### Requirements

* rust-lang
* golang

### Setup Environment

```bash
cargo install protobuf
cargo install bindgen

# Linux(Centos/RHEL)
yum install -y clang-libs clang-devel

# Linux(Ubuntu)
apt-get install llvm-dev libclang-dev clang
```

### Based On Enclave-TLS [enclave-tls](https://github.com/alibaba/inclavare-containers/tree/master/enclave-tls)

#### Build

* verdictd

```bash
cd ${ROOT_DIR}/verdictd/
make
```

#### Run

verdictd supports tcp socket, and sockaddr can be an address form similar to `127.0.0.1:1122`.

```bash
cd ${ROOT_DIR}/verdictd/
./bin/verdictd
```