# Attestation Evidence Broker (AEB)

## Introduction

Attestation Evidence Broker (AEB) is a host service to satisfy the requests from guest for getting attestation evidence.

In theory, the attester is responsible for generating the attestation evidence. In practice, certain TEE, e.g, SEV(-ES), needs the help from untrusted host side to retrieve the attestation evidence.

Currently, AEB only supports SEV(-ES) runtime attestation. In future, it will support Intel TDX.

## Design

Please refer to [design document](docs/design/design.md) for more information.

## Usage

Here are the steps of building and running AEB:

### Build

Build and install AEB:

```shell
git clone https://github.com/alibaba/inclavare-containers
cd inclavare-containers/attestation-evidence-broker
make && make install
```

### Run

For help information, just run:

```shell
aeb --help
SEV Attestation Evidence Broker 0.0.1

SEV Attestation Evidence Broker for provide evidence for guest attestation agent

USAGE:
    aeb [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -l, --listen <listen>    Specify the socket listen addr. For example: vsock:///tmp/aeb.sock, unix:///tmp/aeb.sock
    -p, --port <port>        Specify the socket listen port. Default is 5577
```

Start AEB:

```shell
aeb
```
