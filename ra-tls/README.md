# Before you start
- Refer to [this guide](https://github.com/alibaba/inclavare-containers#rune) to build `rune` from scratch.
- Register a `SPID` and `Subscription Key` of [IAS](https://api.portal.trustedservices.intel.com/EPID-attestation). After the registration, Intel will respond with a SPID which is needed to communicate with IAS.

# Run stub with Docker
## Configure SGX RA settings
```shell
export SPID=<hex string>
export EPID_SUBSCRIPTION_KEY=<hex string>
export QUOTE_TYPE=<SGX_LINKABLE_SIGNATURE | SGX_UNLINKABLE_SIGNATURE>
```

## Install dependency
```shell
yum install -y patch autoconf automake libtool
```

## Build liberpal-stub
```shell
cd "${path_to_inclavare_containers}/ra-tls"
make
cp pal/liberpal-stub.so /usr/lib
```

# Build stub container image
```shell
cd "${path_to_inclavare_containers}/ra-tls/stub-enclave"
cat >Dockerfile <<EOF
FROM ubuntu:18.04
  
RUN mkdir -p /run/rune/stub-enclave
WORKDIR /run/rune

COPY Wolfssl_Enclave.signed.so  stub-enclave
EOF
docker build -t stub-enclave .
```

# Run stub container image with rune
## Configure OCI runtime
Refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md#configure-oci-runtime) to configure OCI runtime in dockerd config file.

## Run stub container image with rune
```shell
docker run -it --rm --runtime=rune -e ENCLAVE_TYPE=intelSgx \
	-e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-stub.so \
	-e ENCLAVE_RUNTIME_ARGS=stub-enclave stub-enclave
```

# Run stub OCI bundle
## Create stub bundle
In order to use `rune` you must have your container image in the format of an OCI bundle. If you have Docker installed you can use its `export` method to acquire a root filesystem from an existing stub-enclave Docker container image.

```shell
# create the top most bundle directory
cd "$HOME/rune_workdir"
mkdir rune-container
cd rune-container

# create the rootfs directory
mkdir rootfs

# export stub-enclave image via Docker into the rootfs directory
docker export $(docker create stub-enclave) | sudo tar -C rootfs -xvf -
```

After a root filesystem is populated you just generate a spec in the format of a config.json file inside your bundle. `rune` provides a spec command which is similar to `runc` to generate a template file that you are then able to edit.

```shell
rune spec
```

To find features and documentation for fields in the spec please refer to the [specs](https://github.com/opencontainers/runtime-spec) repository.

In order to run the stub-enclave bundle with `rune`, you need to configure enclave runtime as following:
```json
  "annotations": {
      "enclave.type": "intelSgx",
      "enclave.runtime.path": "/usr/lib/liberpal-stub.so",
      "enclave.runtime.args": "stub-enclave"
  }
```

where:
- @enclave.type: specify the type of enclave hardware to use, such as intelSgx.
- @enclave.runtime.path: specify the path to enclave runtime to launch.
- @enclave.runtime.args: specify the specific arguments to enclave runtime, seperated by the comma.

## Run stub
Assuming you have an OCI bundle from the previous step you can execute the container in this way.

```shell
cd "$HOME/rune_workdir/rune-container"
sudo rune run stub-enclave-container
```
