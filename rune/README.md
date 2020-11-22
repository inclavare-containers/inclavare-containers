# rune

`rune` is a CLI tool for spawning and running enclaves in containers according to the OCI specification.

# Building

`rune` currently supports the Linux platform with x86-64 architecture only. It must be built with Go version 1.14 or higher.

Additionally, `rune` by default enables seccomp support as [runc](https://github.com/opencontainers/runc#building) so you need to install libseccomp on your platform.

```bash
# create $WORKSPACE folder
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
git clone https://github.com/alibaba/inclavare-containers
cd inclavare-containers/rune

# build and install rune
make
sudo make install
```

`rune` will be installed to `/usr/local/bin/rune` on your system.

# Using rune

## How to launch rune

`rune` is OCI Runtime specification compatible container engine. It can be integrated with containerd and docker.

Please refer to [these steps](../README.md#integrating) for the integration guide.

## What can be launched by rune

In the downstream of `rune`, various enclave runtimes can be launched by `rune` through well-defined [Enclave Runtime PAL API](libenclave/internal/runtime/pal/spec.md).

### Skeleton

Skeleton is an example of enclave runtime, interfacing with Enclave Runtime PAL API for easy interfacing with `rune`.  Skeleton sample code is helpful to write your own enclave runtime.

Please refer to [this tutorial](libenclave/internal/runtime/pal/skeleton/README.md) for more details.

### Occlum

[Occlum](https://github.com/occlum/occlum) is a memory-safe, multi-process library OS for Intel SGX. 

Please refer to [this tutorial](https://github.com/occlum/occlum/blob/master/docs/rune_quick_start.md) for more details.

### WebAssembly Micro Runtime (WAMR)

[WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) is a standalone WebAssembly (WASM) runtime with a small footprint, including a VM core, an application framework and a dynamic management for WASM applications.

Please refer to [this tutorial](https://github.com/bytecodealliance/wasm-micro-runtime/tree/main/product-mini/platforms/linux-sgx/enclave-sample/App#wamr-as-an-enclave-runtime-for-rune) for more details.

# Developement

Taking Occlum as example to show how to run OCI bundle.

## Create container image

Please refer to [this guide](https://github.com/occlum/occlum/blob/master/docs/rune_quick_start.md#building-occlum-container-image) to build the Occlum application container image.

## Creating an OCI bundle

In order to use `rune` you must have your container image in the format of an OCI bundle. If you have Docker installed you can use its `export` method to acquire a root filesystem from an existing Occlum application container image. 

```shell
# create the top most bundle directory
mkdir -p "$HOME/rune_workdir" 
cd "$HOME/rune_workdir"
mkdir rune-container
cd rune-container

# create the rootfs directory
mkdir rootfs

# export Occlum application image via Docker into the rootfs directory
docker export $(docker create occlum-app) | sudo tar -C rootfs -xvf -
```

After a root filesystem is populated you just generate a spec in the format of a config.json file inside your bundle. `rune` provides a spec command which is similar to `runc` to generate a template file that you are then able to edit.

```shell
rune spec
```

To find features and documentation for fields in the spec please refer to the [specs](https://github.com/opencontainers/runtime-spec) repository.

In order to run the hello world demo program in Occlum with `rune`, you need to change the entrypoint from `sh` to `/bin/hello_world`
``` json
  "process": {
      "args": [
          "/bin/hello_world"
      ],
  }
```

and then configure enclave runtime as following:
``` json
  "annotations": {
      "enclave.type": "intelSgx",
      "enclave.runtime.path": "/opt/occlum/build/lib/libocclum-pal.so",
      "enclave.runtime.args": "occlum_instance"
  }
```

where:
- @enclave.type: specify the type of enclave hardware to use, such as `intelSgx`.
- @enclave.runtime.path: specify the path to enclave runtime to launch. For an Occlum application, you need to specify the path to `libocclum-pal.so`.
- @enclave.runtime.args: specify the specific arguments to enclave runtime, separated by the comma.

## Run Occlum application
Assuming you have an OCI bundle from the previous step you can execute the container in this way.

```shell
cd "$HOME/rune_workdir/rune-container"
sudo rune run ${Occlum_application_container_name}
```

# Credits

Some codes in rune have been borrowed from [runc](https://github.com/opencontainers/runc) project.
