# Introduction

`attester` is a sample guest application that communicates with AEB through VSOCK to query attestation evidence.

# Usage

You can use `cargo build --release` to compile and place the generated executable file in the `/bin` directory.

The basic usage is as follows.

```shell
attester -h
Sample attester 0.1.0

A sample attester connecting to AEB to query SEV attestation evidence

USAGE:
    attester [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --connect <connect>    Specify the socket connect addr. For example: vsock:///tmp/aeb.sock, unix:///tmp/aeb.sock
    -p, --port <port>          Specify the socket listen port. Default is 5577
```

# RUN

Please run the following command in the guest environment to start the sample `attester` application.

```shell
attester -c vsock:///tmp/aeb.sock -p 5577
```
