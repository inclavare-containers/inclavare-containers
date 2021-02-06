# Introduction

This guide will show you how to use EPID-based remote attestation in skeleton with rune.

# Before you start

- Build `rune` according to this [guide](https://github.com/alibaba/inclavare-containers/tree/master/rune#building).

- Build `EPID` or `DCAP` ra-tls according to this [guide](https://github.com/alibaba/inclavare-containers/blob/master/ra-tls/README.md#build).

# Quick Start

## Build and install the PAL of skeleton enclave runtime

Please refer to [guide](https://github.com/alibaba/inclavare-containers/tree/master/rune/libenclave/internal/runtime/pal/skeleton#build-and-install-the-pal-of-skeleton-enclave-runtime) to install the dependencies of skeleton enclave runtime.

Then type the follwing comamnds to build and install the PAL of skeleton enclave runtime.

```shell
cd "${path_to_inclavare_containers}/rune/libenclave/internal/runtime/pal/skeleton"
make TLS_SERVER=1
cp liberpal-skeleton-v3.so /usr/lib
```

## Build skeleton docker image

### Build EPID-based remote attestation skeleton docker image

Skeleton enclave runtime requires to authenticate Intel IAS https server, so it is required to include the necessary certificates in skeleton docker image.

On Red Hat/Centos, `ca-bundle.trust.crt` includes all trusted certificate authorities.

```shell
/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt
```

On Debian/Ubuntu just use this file for verification.

```shell
/etc/ssl/certs/ca-certificates.crt
```

Assume your host is ubuntu 18.04:

Type the following commands to create a Dockerfile:

```Dockerfile
cp /etc/ssl/certs/ca-certificates.crt ./
cp ${path_to_inclavare_containers}/ra-tls/build/bin/Wolfssl_Enclave.signed.so ./
cat >Dockerfile <<EOF
FROM centos:8.1.1911

WORKDIR /

COPY Wolfssl_Enclave.signed.so /

RUN mkdir -p /etc/ssl/certs/
COPY ca-certificates.crt /etc/ssl/certs/
EOF
```

If your host system is CentOS 8.1, please copy the `/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt` rather than `/etc/ssl/certs/ca-certificates.crt` to the skeleton docker image.

Then build the skeleton docker image with the command:

```shell
docker build . -t skeleton-enclave
```

### Build DCAP-based remote attestation skeleton docker image

Assume your host is CentOS.

Type the following commands to create a Dockerfile:

```Shell
cp ${path_to_inclavare_containers}/ra-tls/build/bin/Wolfssl_Enclave.signed.so ./
cp /etc/sgx_default_qcnl.conf ./
cp /usr/lib64/libsgx_pce.signed.so ./
cp /usr/lib64/libsgx_qe3.signed.so ./

cat >Dockerfile <<EOF
FROM centos:8.1.1911

WORKDIR /

COPY Wolfssl_Enclave.signed.so /

COPY sgx_default_qcnl.conf /etc/

COPY libsgx_pce.signed.so /usr/lib64
COPY libsgx_qe3.signed.so /usr/lib64
EOF
```

Then build the skeleton docker image with the command:

```shell
docker build . -t skeleton-enclave
```

## Integrate OCI Runtime rune with Docker

Please refer to [guide](https://github.com/alibaba/inclavare-containers/tree/master/rune/libenclave/internal/runtime/pal/skeleton#integrate-oci-runtime-rune-with-docker) to integrate OCI runtime rune with docker.

## Run skeleton with TLS server

At present, TLS server based on EPID is only implemented in skeleton v3.

### Run EPID TLS server by docker image

```shell
docker run -i --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-skeleton-v3.so \
  -e ENCLAVE_RUNTIME_ARGS=debug \
  -v /run/rune:/run/rune \
  skeleton-enclave:latest
```

### Run DCAP TLS server by docker image

```shell
docker run -i --rm --net=host --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-skeleton-v3.so \
  -e ENCLAVE_RUNTIME_ARGS=debug \
  -v /run/rune:/run/rune \
  skeleton-enclave:latest
```

The following method to run skeleton bundle with rune is usually provided for developmemt purpose.

### Run TLS server by OCI bundle

Assuming you have an OCI bundle according to [previous steps](skeleton#create-skeleton-bundle), please add config into config.json as following:

```shell
"cwd": "/",

"annotations": {
        "enclave.type": "intelSgx",
        "enclave.runtime.path": "/usr/lib/liberpal-skeleton-v3.so",
        "enclave.runtime.args": "debug"
}

{
        "destination": "/run/rune",
        "type": "bind",
        "source": "/run/rune",
        "options": [
                "rbind",
                "rprivate"
        ]
}
```

If you want to run `DCAP` OCI bundle, you alse need to delete the network namespace configuration in config.json to ensure you run skeleton in host network mode. After doing this, your namespaces is as following without the network type namespace:

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

## Run TLS client

```shell
cd "${path_to_inclavare_containers}/ra-TLS/build/bin"
./elv echo
```
