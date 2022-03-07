# Introduction

This guide will show you how to use remote attestation in skeleton with rune and enclave-tls.

# Before you start

- Build and install `rune` according to this [guide](https://github.com/alibaba/inclavare-containers/tree/master/rune#building).

- Build and install `enclave-tls` according to this [guide](https://github.com/alibaba/inclavare-containers/blob/master/enclave-tls/README.md).

# Quick Start

## Build and install the PAL of skeleton enclave runtime

Please refer to [guide](https://github.com/alibaba/inclavare-containers/tree/master/rune/libenclave/internal/runtime/pal/skeleton#build-and-install-the-pal-of-skeleton-enclave-runtime) to install the dependencies of skeleton enclave runtime.

Then type the following commands to build and install the PAL of the skeleton enclave runtime.

```shell
cd "${path_to_inclavare_containers}/rune/libenclave/internal/runtime/pal/skeleton"
make TLS_SERVER=1
cp liberpal-skeleton-v3.so /usr/lib
```

## Build skeleton docker image

### Build ECDSA remote attestation skeleton docker image

Type the following commands to create a Dockerfile:

#### On Ubuntu 18.04

```Shell
cp /opt/enclave-tls/bin/sgx_stub_enclave.signed.so ./
cp /etc/sgx_default_qcnl.conf ./
cp /usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so ./
cp /usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so ./

cat >Dockerfile <<EOF
FROM ubuntu:18.04

WORKDIR /

COPY sgx_stub_enclave.signed.so /

COPY sgx_default_qcnl.conf /etc/

COPY libsgx_pce.signed.so /usr/lib/x86_64-linux-gnu
COPY libsgx_qe3.signed.so /usr/lib/x86_64-linux-gnu
EOF
```

Then build the skeleton docker image with the command:

```shell
docker build . -t skeleton-enclave
```

### Build local report attestation skeleton docker image

Type the following commands to create a Dockerfile:

#### On Ubuntu 18.04

```Shell
cp /opt/enclave-tls/bin/sgx_stub_enclave.signed.so ./

cat >Dockerfile <<EOF
FROM ubuntu:18.04

WORKDIR /

COPY sgx_stub_enclave.signed.so /

EOF
```

Then build the skeleton docker image with the command:

```shell
docker build . -t skeleton-enclave
```

## Integrate OCI Runtime rune with Docker

Please refer to [guide](https://github.com/alibaba/inclavare-containers/tree/master/rune/libenclave/internal/runtime/pal/skeleton#integrate-oci-runtime-rune-with-docker) to integrate OCI runtime rune with docker.

## Run skeleton with TLS server

At present, TLS server based on `enclave-tls` is only implemented in skeleton v3.

### Run ECDSA TLS server by docker image

```shell
docker run -i --rm --net=host --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-skeleton-v3.so \
  -e ENCLAVE_RUNTIME_ARGS="debug attester=sgx_ecdsa tls=openssl crypto=openssl" \
  skeleton-enclave:latest
```

### Run local report attestation TLS server by docker image

```shell
docker run -i --rm --net=host --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-skeleton-v3.so \
  -e ENCLAVE_RUNTIME_ARGS="debug attester=sgx_la tls=openssl crypto=openssl" \
  skeleton-enclave:latest
```

The following method to run skeleton bundle with rune is usually provided for development purposes.

### Run TLS server by OCI bundle

Assuming you have an OCI bundle according to [previous steps](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton#create-skeleton-bundle), please add config into config.json as following:

```shell
"cwd": "/",

"annotations": {
        "enclave.type": "intelSgx",
        "enclave.runtime.path": "/usr/lib/liberpal-skeleton-v3.so",
        "enclave.runtime.args": "debug attester=sgx_ecdsa tls=openssl crypto=openssl"
}
```

If you do NOT set runtime parameters in `enclave.runtime.args`, TLS server will run the highest priority `enclave quote/tls wrapper/crypto` instance. Please refer to this [guide](https://github.com/alibaba/inclavare-containers/blob/master/enclave-tls/README.md#run) for more information.

Remember that you also need to delete the network namespace configuration in config.json to ensure you run skeleton in host network mode. After doing this, your namespaces are as following without the network type namespace:

```shell
                "namespaces": [
                        {
                                "type": "pid"
                        },
                        {
                                "type": "ipc"
                        },
                        {
                                "type": "uts"
                        },
                        {
                                "type": "mount"
                        }
                ],
```

Assuming you have an OCI bundle from the previous step you can execute the container in this way.

```shell
cd "$HOME/rune_workdir/rune-container"
sudo rune run skeleton-enclave-container
```

If you run the skeleton image in the docker environment, you might meet the problem as follow.
 
```
[get_platform_quote_cert_data ../qe_logic.cpp:346] Error returned from the p_sgx_get_quote_config API. 0xe019
[ERROR] sgx_qe_get_target_info() with error code 0xe019
[get_platform_quote_cert_data ../qe_logic.cpp:346] Error returned from the p_sgx_get_quote_config API. 0xe019
[ERROR] sgx_qe_get_quote_size(): 0xe019
```

Please type the following code to solve the problem

```shell
cp /etc/resolv.conf rootfs/etc/
```

## Run Enclave TLS client on sgx platform

```shell
cd /opt/enclave-tls/bin
# run sgx_ecdsa remote attestation
./enclave-tls-client -a sgx_ecdsa -t openssl -c openssl
# run sgx_la remote attestation
./enclave-tls-client -a sgx_la -t openssl -c openssl
```

## Run Enclave TLS client on non-sgx platform

Only support run remote attestation based on ecdsa.

```shell
cd /opt/enclave-tls/bin
# run sgx_ecdsa remote attestation
./enclave-tls-client -v sgx_ecdsa -t openssl -c openssl
```
