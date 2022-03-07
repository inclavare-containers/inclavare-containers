![inclavare-containers](docs/images/logo.png)

[![Nightly Ubuntu SGX1](https://github.com/alibaba/inclavare-containers/workflows/Nightly%20Ubuntu%20SGX1/badge.svg?branch=master)](https://github.com/alibaba/inclavare-containers/actions?query=workflow%3A%22Nightly+Ubuntu+SGX1%22)
[![Nightly Alibaba Cloud Linux2 SGX2](https://github.com/alibaba/inclavare-containers/actions/workflows/nightly-aliyunlinux-sgx2.yml/badge.svg?branch=master)](https://github.com/alibaba/inclavare-containers/actions/workflows/nightly-aliyunlinux-sgx2.yml)

Inclavare, pronounced as `[ˈinklɑveə]`, is the Latin etymology of the word `enclave`, which means to isolate the user's sensitive workload from the untrusted and uncontrollable infrastructure in order to meet the protection requirement for the data in use.

Inclavare Containers is an innovation of container runtime with the novel approach for launching protected containers in hardware-assisted Trusted Execution Environment (TEE) technology, aka Enclave, which can prevent the untrusted entity, such as Cloud Service Provider (CSP), from accessing the sensitive and confidential assets in use.

Inclavare Containers has the following salient features:

- Confidential computing oriented. Inclavare Containers provides a general design for the protection of tenant’s workload. 
  - Create the hardware-enforced isolation between tenant’s workload and privileged software controlled by CSP.
  - Remove CSP from the Trusted Computing Base (TCB) of tenant in untrusted cloud.
  - Construct the general attestation infrastructure to convince users to trust the workloads running inside TEE based on hardware assisted enclave technology.
- OCI-compliant. The component `rune` is [fully compliant](https://github.com/opencontainers/runtime-spec/blob/master/implementations.md#runtime-container) with OCI Runtime specification.
- Cloud platform agnostic. It can be deployed in any public cloud Kubernetes platform.

Please refer to [Terminology](docs/design/terminology.md) for more technical expressions used in Inclavare Containers.

![cncf](docs/images/cncf.png)

Inclavare Containers is a [sandbox project](https://www.cncf.io/projects/inclavare-containers/) of the [Cloud Native Computing Foundation (CNCF)](https://www.cncf.io/). If you are an organization that wants to help shape the evolution of technologies that are container-packaged, dynamically-scheduled and microservices-oriented, consider joining the CNCF.

# Audience

Inclavare Containers is helping to keep tenants' confidential data secure so they feel confident that their data is not being exposed to CSP or their own insiders, and they can easily move their trusted applications to the cloud.

# Architecture

Inclavare Containers follows the classic container runtime design. It takes the adaption to [containerd](https://github.com/containerd/containerd) as first class, and uses dedicated [shim-rune](https://github.com/alibaba/inclavare-containers/tree/master/shim) to interface with OCI Runtime [rune](https://github.com/alibaba/inclavare-containers/tree/master/rune). In the downstrem, [init-runelet](docs/design/terminology.md#init-runelet) employs a novel approach of launching [enclave runtime](docs/design/terminology.md#enclave-runtime) and trusted application in hardware-enforced enclave.

![architecture](docs/design/architecture.png)

The major components of Inclavare Containers are:

- rune  
  rune is a CLI tool for spawning and running enclaves in containers according to the OCI specification. rune is already written into [OCI Runtime implementation list](https://github.com/opencontainers/runtime-spec/blob/master/implementations.md#runtime-container).

- shim-rune  
  shim-rune resides in between containerd and `rune`, conducting enclave signing and management beyond the normal `shim` basis. In particular shim-rune and `rune` can compose a basic enclave containerization stack for confidential computing, providing low barrier to the use of confidential computing and the same experience as ordinary container. Please refer to [this doc](shim/README.md) for the details.

- enclave runtime  
  The backend of `rune` is a component called enclave runtime, which is responsible for loading and running trusted and protected applications inside enclaves. The interface between `rune` and enclave runtime is [Enclave Runtime PAL API](rune/libenclave/internal/runtime/pal/spec.md), which allows invoking enclave runtime through well-defined functions. The softwares for confidential computing may benefit from this interface to interact with cloud-native ecosystem.  
  
  One typical class of enclave runtime implementations is based on Library OSes. Currently, the recommended enclave runtime interacting with `rune` is [Occlum](https://github.com/occlum/occlum), a memory-safe, multi-process Library OS for Intel SGX.  And another typical class of enclave runtime is [WebAssembly Micro Runtime (WAMR)](https://github.com/bytecodealliance/wasm-micro-runtime) with Intel SGX, a standalone WebAssembly (WASM) runtime with a small footprint, including a VM core, an application framework and a dynamic management for WASM applications.
  
  In addition, you can write your own enclave runtime with any programming language and SDK (e.g, [Intel SGX SDK](https://github.com/intel/linux-sgx)) you prefer as long as it implements Enclave Runtime PAL API.

# Attestation

Inclavare Containers implements Enclave Attestation Architecture (EAA), a universal and cross-platform remote attestation infrastructure. EAA can prove that sensitive workloads are running on a genuine and trusted hardware TEE based on confidential computing technology. The formal design of EAA will be published for RFC.

![architecture](docs/design/eaa_demo.png)

The major components of EAA are:

- [Rats-TLS](https://github.com/alibaba/inclavare-containers/tree/master/rats-tls) 
  `Rats-TLS` enhances the standard TLS to support the trusted communications between heterogeneous hardware TEEs based on confidential computing technology, which is evolved from the [ra-tls (deprecated)](https://github.com/alibaba/inclavare-containers/tree/master/ra-tls). Even a non-hardware TEE platforms using `Rats-TLS` can communicate with a hardware TEE, e.g, SGX Enclave, through the attested and secured channel to transmit the sensitive information. In other words, the boundary of TCB is extended from execution environment to network transmission with `Rats-TLS`. In addition, `Rats-TLS` has an extensible model to support various hardware TEE. Refer to [this design doc](rats-tls/docs/design/design.md) for more details.

- Confidential Container  
  Confidential container in the form of the enclave runtime `Occlum` responds to the request from `Inclavared`, and then sends back the attestation evidence of confidential container to `Inclavared`. Confidential container plays the role of the attester.

- [Inclavared](https://github.com/alibaba/inclavare-containers/tree/master/inclavared)  
  `Inclavared` is responsible for forwarding the traffic between the confidential container and `Shelter`. The communication process is protected by the attested `Enclave-TLS` channel.

- [Shelter](https://github.com/alibaba/inclavare-containers/tree/master/shelter)  
  `Shelter`, as the role of the verifier deployed in the off-cloud, records the launch measurements of enclave runtime, and afterward establishes the attested `Enclave-TLS` channel to communicate with `Inclavared`. Eventually, it retrieves the evidence about enclave runtimes for verification.

# Non-core components 

- sgx-tools  
  sgx-tools is a CLI tool, used to interact Intel SGX AESM service to retrieve various materials such as launch token, quoting enclave's target information, enclave quote and remote attestation report from IAS. Refer to [this tutorial](sgx-tools/README.md) for the details about its usage.

- epm  
  epm is a service that is used to manage the cache pools to optimize the startup time of enclave. Refer to [this tutorial](epm/README.md) for the details about its usage.

# Roadmap

Please refer to [Inclavare Containers Roadmap](ROADMAP.md) for the details. This document outlines the development roadmap for the Inclavare Containers project.

# Building

It's recommended to use [Inclavare Containers development docker image](https://hub.docker.com/repository/docker/inclavarecontainers/dev) to build Inclavare Containers from scratch.

Note that the environment of launching Inclavare Containers development docker image must be capable of hardware TEE and install the corresponding software stack, e.g, Intel SGX and [Intel SGX SDK & PSW for Linux](https://download.01.org/intel-sgx/sgx-linux/2.14/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf).

The exact command to run the docker image requires to be specified explicitly according to the type of SGX device driver.

- For legacy out-of-tree driver:

```shell
docker run -it -v /var/run/aesmd:/var/run/aesmd \
  -device /dev/isgx \
  inclavarecontainers/dev:$version-$os
```

- For DCAP and in-tree driver:

```shell
docker run -it -v /var/run/aesmd:/var/run/aesmd \
  -v /dev/sgx_enclave:/dev/sgx/enclave -v /dev/sgx_provision:/dev/sgx/provision \
  inclavarecontainers/dev:$version-$os
```

where:
- `$version` denotes the version of Inclavare Containers in use.
- `$os` denotes the OS type of development docker image, which may be ubuntu18.04 or alinux2.

Please be aware of running the commands listed below in the development container launched by Inclavare Containers development docker image.

1. Download the latest source code of Inclavare Containers

```shell
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
git clone https://github.com/alibaba/inclavare-containers
```

2. Build Inclavare Containers

```shell
cd inclavare-containers
# build rune, shim-rune, epm, sgx-tools, enclave-tls, shelter and inclavared
make
```

# Installing

After build Inclavare Containers on your system, you can use the following command to install Inclavare Containers on your system.

```shell
sudo make install
```

`{rune,shim-rune,epm,sgx-tools,shelter,inclavared}` will be installed to `/usr/local/bin/{rune,containerd-shim-rune-v2,epm,sgx-tools,shelter,inclavared}` on your system. Enclave-TLS SDK will be installed to `/opt/enclave-tls`. `{enclave-tls-server,enclave-tls-client}` will be installed to `/usr/share/enclave-tls/samples`.

If you don't want to build and install Inclavare Containers from latest source code. We also provide RPM/DEB repository to help you install Inclavare Containers quickly. Please see the [steps about how to configure repository](https://github.com/alibaba/inclavare-containers/blob/master/docs/create_a_confidential_computing_kubernetes_cluster_with_inclavare_containers.md#1-add-inclavare-containers-repository) firstly. Then you can run the following command to install Inclavare Containers on your system.

- On Ubuntu 18.04 server

```
sudo apt-get install rune shim-rune epm sgx-tools enclave-tls shelter inclavared
```

# Integrating

Inclavare Containers can be integrated with dockerd, containerd, and [pouchd](https://github.com/alibaba/pouch).

The former targets using docker to deploy Inclavare Containers. Specifically, you need to install the preferred enclave runtime when building container images, and then launch the enclave runtime through `rune` and [enclave runtime specific PAL](docs/design/terminology.md#enclave-runtime-pal).

The latter targets using K8s to deploy Inclavare Containers. In this scenario, `shim-rune` and `rune` can compose an enclave containerization stack, so enclave runtime is not required and installed when building container images, providing with the same experience as ordinary containers.

## dockerd

Add the assocated configurations for `rune` in dockerd config file, e.g, `/etc/docker/daemon.json`, on your system.

```json
{
        "runtimes": {
                "rune": {
                        "path": "/usr/local/bin/rune",
                        "runtimeArgs": []
                }
        }
}
```

then restart dockerd on your system.

You can check whether `rune` is correctly enabled or not with:

```shell
docker info | grep rune
```

Note that the systemd is not installed by default, so please manually start up dockerd:

```shell
dockerd -b docker0 --storage-driver=vfs &
```

## containerd 

Inclavare Containers is added to the [adopters list of containerd](https://github.com/containerd/containerd/blob/master/ADOPTERS.md). Besides, `shim-rune` supports [containerd shim v2 API](https://github.com/containerd/containerd/blob/master/runtime/v2/task/shim.proto). So you can add the assocated configurations for `shim-rune` in the `containerd` config file, e.g, `/etc/containerd/config.toml`, on your system.

```toml
        [plugins.cri.containerd]
          ...
          [plugins.cri.containerd.runtimes.rune]
            runtime_type = "io.containerd.rune.v2"
```

then restart containerd on your system.

## pouchd

Add the assocated configurations in pouchd config file, e.g, `/etc/pouch/config.json`, on your system.

```json
	"add-runtime": {
		"rune": {
            		"path": "/usr/local/bin/rune",
            		"runtimeArgs": null,
            		"type": "io.containerd.rune.v2"
        	},
		...
	}	
```

where:
- @path: specify the path of OCI Runtime, such as the pach of `rune`.
- @runtimeArgs: specify the arguments of the pouchd runtime, such as `--platform`, `--network`.
- @type: specify the shim template from the following candidates:
	- io.containerd.rune.v2: correspond to shim-rune
	- io.containerd.runtime.v1.linux: correspond to containerd-shim
	- io.containerd.runc.v1: correspond to containerd-shim-runc-v1

then restart pouchd on your system.

You can check whether `rune` is correctly enabled or not with:

```shell
pouch info | grep rune
```

# Deployment

Inclavare Containers can be deployed with Occlum LibOS and WebAssembly Micro Runtime (WAMR).

## Occlum LibOS

Please refer to [this guide](https://github.com/occlum/occlum/blob/master/docs/rune_quick_start.md) to run [Occlum](https://github.com/occlum/occlum) with `rune` and docker.

Please refer to [this guide](docs/develop_and_deploy_hello_world_application_in_kubernetes_cluster.md) to deploy an enclave container in a Kubernetes cluster. Currently, [Hello-world application image](https://hub.docker.com/r/inclavarecontainers/occlum-hello-world) and web application images based on [OpenJDK 11](https://hub.docker.com/r/inclavarecontainers/occlum-java-web), [Dragonwell](https://hub.docker.com/r/inclavarecontainers/occlum-dragonwell-web), and [Golang](https://hub.docker.com/r/inclavarecontainers/occlum-golang-web) are provided. These images don't contain enclave runtime. They are only used for the deployment with containerd.

Please refer to [this guide](docs/running_inclavare_containers_with_pouch_and_occlum.md) to run inclavare-containers with `pouchd`.

## WebAssembly Micro Runtime (WAMR)

Please refer to [this guide](https://github.com/bytecodealliance/wasm-micro-runtime/tree/main/product-mini/platforms/linux-sgx/enclave-sample/App#wamr-as-an-enclave-runtime-for-rune) to run [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) with `rune`.

[WebAssembly Micro Runtime (WAMR) application image](https://hub.docker.com/r/inclavarecontainers/enclave-wamr/tags) is provided. WAMR image contains enclave runtime, because it doesn't adapt to shim-rune and use off-cloud signing. It is only used for the deployment with dockerd.


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Falibaba%2Finclavare-containers.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Falibaba%2Finclavare-containers?ref=badge_large)
