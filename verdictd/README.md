
# Introduction

Verdictd is a remote attestation implementation comprising of a set of building blocks that utilize Intel/AMD Security features to discover, attest, and enable critical foundation security and confidential computing use-cases. 
It relies on [RATS-TLS](https://github.com/alibaba/inclavare-containers/tree/master/rats-tls) to apply the remote attestation fundamentals and standard specifications to maintain a platform data collection service and an efficient verification engine to perform comprehensive trust evaluations. 
These trust evaluations can be used to govern different trust and security policies applied to any given workload.

Verdictd creates an m-TLS(Mutal Transport Layer Security) connection with [Attestation Agent](https://github.com/confidential-containers/attestation-agent) via remote attestation.
Mainly functions:
- Implemented verdictd's protocol which includes "decryption" and "get KEK" requests.
- Implemented a ocicrypto [containers/ocicrypto](https://github.com/containers/ocicrypt) compatible gRPC service.
- Implemented a grpc service which can be used to config OPA's policy files.

# Design

Please refer [design doc](https://github.com/alibaba/inclavare-containers/tree/master/eaa/verdictd/docs/design) to view the design of verdictd.

# Build Source Code

## Requirements

* rust-lang
* golang

## Setup Environment

Please refer [Download OPA](https://www.openpolicyagent.org/docs/latest/#1-download-opa) to install OPA tool.
```bash
curl -L -o opa https://openpolicyagent.org/downloads/v0.30.1/opa_linux_amd64_static
chmod 755 ./opa
mv opa /usr/local/bin/opa
```

Install bindgen tool
```bash
cargo install protobuf
cargo install bindgen

# Linux(Centos/RHEL)
yum install -y clang-libs clang-devel

# Linux(Ubuntu)
apt-get install llvm-dev libclang-dev clang
```

## Build & Install

```bash
cd ${ROOT_DIR}/verdictd/
make
make install
```

# Run

Verdictd relies on rats-tls to listen on tcp socket, the default sockaddr is `127.0.0.1:1234`.
User can use `--listen` option to specify a listen address.
```bash
verdictd --listen 127.0.0.1:1111
```
User can use `--attester`, `--verifier`, `--tls`, `--crypto` and `--mutual` options to specific rats-tls uses instances's type. See details: [RATS-TLS](https://github.com/alibaba/inclavare-containers/tree/master/rats-tls)

User can use `--gRPC` option to specify grpc server's listen address which supports key provider protocol.
```bash
verdictd --gRPC [::1]:10000
```

User can use `--config` option to specify configuration server's listen address.
```bash
verdictd --config [::1]:10001
```

## Default

These options all exist default values. If user execute `./bin/verdictd` directly, it will execute with following configurations.
```bash
verdictd --listen 127.0.0.1:1234 --gRPC [::1]:50000 --config [::1]:60000
```

# Generate encrypted container image

Verdictd supports key provider protocol's `WrapKey` request by the address designated by `--gRPC` option. 
So user can use Verdictd and skopeo to generate encrypted container image with the following steps.
```
# Generate the key provider configuration file
cat <<- EOF >/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf
{
        "key-providers": {
                "attestation-agent": {
                    "grpc": "127.0.0.1:50001"

                }
        }
}
EOF

# Generate a encryption key
cat <<- EOF >/opt/verdictd/keys/84688df7-2c0c-40fa-956b-29d8e74d16c0
1234567890123456789012345678901
EOF

# Launch Verdictd
verdictd --gRPC 127.0.0.1:50001

skopeo --insecure-policy copy docker://docker.io/library/alpine:latest oci:alpine

export OCICRYPT_KEYPROVIDER_CONFIG=/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf

# generate encrypted image
skopeo copy --insecure-policy --encryption-key provider:attestation-agent:84688df7-2c0c-40fa-956b-29d8e74d16c0 oci:alpine oci:alpine-encrypted
```

# Substree testing