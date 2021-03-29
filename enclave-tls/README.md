# enclave-tls

## Build

### Build Requirements

- git
- make
- autoconf
- automake
- libtool
- go version 1.14 or higher

### Build and Install

```shell
cd inclavare-containers/enclave-tls
make
make install
```

## Run

```shell
cd inclavare-containers/enclave-tls/bin
mkdir -p /run/enclave-tls
./ra-tls-server run &
./elv echo
```
