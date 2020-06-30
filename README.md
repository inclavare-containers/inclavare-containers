# inclavare-containers

## Introduction
`inclavare-containers` is a set of tools for running trusted applications in containers with the hardware-assisted enclave technology. Enclave, referred to as a protected execution environment, prevents the untrusted entity from accessing the sensitive and confidential assets in use.

## Components
### rune
`rune` is a CLI tool for spawning and running enclaves in containers according to the OCI specification. The codebase of `rune` is a fork of [runc](https://github.com/opencontainers/runc), so `rune` can be used as `runc` if enclave is not configured or available.

`rune` currently supports the Linux platform with x86-64 architecture only. It must be built with Go version 1.14 or higher.

`rune` depends on protobuf compiler. Please refer to [this guide](https://github.com/protocolbuffers/protobuf#protocol-compiler-installation) to install it on your platform. Additionally, `rune` by default enables seccomp support as [runc](https://github.com/opencontainers/runc#building) so you need to install libseccomp on your platform. Note that the libseccomp is also required in container environment, and the host version should be equal or higher than the one in container.

```bash
# create $WORKSPACE folder
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
git clone https://github.com/alibaba/inclavare-containers
cd inclavare-containers/rune

# install Go protobuf plugin for protobuf3
go get github.com/golang/protobuf/protoc-gen-go@v1.3.5

# build and install rune
make
sudo make install
```

`rune` will be installed to `/usr/local/sbin/rune` on your system.

### shim-rune
`shim-rune` resides in between `containerd` and `rune`, conducting enclave signing and management beyond the normal `shim` basis. `shim-rune` and `rune` can compose a basic enclave containerization stack for the cloud-native ecosystem.

### enclave runtime
The backend of `rune` is a component called enclave runtime, which is responsible for loading and running protected applications inside enclaves. The interface between `rune` and enclave runtime is [Enclave Runtime PAL API](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/spec.md), which allows invoking enclave runtime through well-defined functions. The software for confidential computing may benefit from this interface to interact with OCI runtime.

One typical class of enclave runtime implementations is based on library OSes. Currently, the default enclave runtime interacting with `rune` is [Occlum](https://github.com/occlum/occlum), a memory-safe, multi-process library OS for Intel SGX.

In addition, you can write your own enclave runtime with any programming language and SDK (e.g, [Intel SGX SDK](https://github.com/intel/linux-sgx)) you prefer as long as it implements Enclave Runtime PAL API.

### runectl
`runectl` is a commandline tool, used to interact Intel SGX aesm service to retrieve various materials such as launch token, Quoting Enclave's target information and enclave quote. Refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/runectl/README.md) for the details about its usage.

---

## Using rune
### Run Occlum
Please refer to [this guide](https://github.com/occlum/occlum/blob/master/docs/rune_quick_start.md) to run `Occlum` with `rune`.

### Run Docker
Please refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/docs/running_rune_with_docker.md) to run `Docker` with `rune`.

### Run skeleton
Skeleton is an example of enclave runtime, interfacing with Enclave Runtime PAL API for easy interfacing with `rune`.  Skeleton sample code is helpful to write your own enclave runtime.

Please refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md) to run skeleton with `rune`.

For more information about Enclave Runtime PAL API, please refer to [Enclave Runtime PAL API Specification](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/spec.md).
