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

### Based On [Enclave-tls](https://github.com/alibaba/inclavare-containers/tree/master/enclave-tls)

#### Build

```bash
cd ${ROOT_DIR}/verdictd/
make
make install
```

#### Run

verdictd relies on enclave-tls to listen on tcp socket, the default sockaddr is `127.0.0.1:1234`.
User can use `--listen` option to specify a listen address.
```bash
./bin/verdictd --listen 127.0.0.1:1111
```
User can use `--attester`, `--verifier`, `--tls`, `--crypto` and `--mutual` options to specific enclave-tls uses instances's type. See details: [Enclave-tls](https://github.com/alibaba/inclavare-containers/tree/master/enclave-tls)

User can use `--gRPC` option to specify grpc server's listen address.
```bash
./bin/verdictd --gRPC [::1]:10000
```
##### Default
These options all exist default values. If user execute `./bin/verdictd` directly, it will execute with following configurations.
```bash
./bin/verdictd --listen 127.0.0.1:1234 --tls openssl --crypto openssl --attester nullattester --verifier sgx_ecdsa --gRPC [::1]:50000
```