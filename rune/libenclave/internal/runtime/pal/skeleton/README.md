The files in this directory are used to implement a skeleton enclave runtime in order to help to write your own enclave runtime.

Note that this code base is inspired by [v28 SGX in-tree driver](https://patchwork.kernel.org/patch/11418925/).

---

# Introduction

Skeleton is an example of enclave runtime, interfacing with Enclave Runtime PAL API for easy interfacing with `rune`.

Based on many engineering practices, skeleton is proven as a best practice on implementing experimental features and PoC. Therefore, some preview features will be implemented in skeleton firstly.

Outline as follows:

- [Quick start](#quick-start)
- [Developement](#developement)
- [Features](#features)

---

# Quick start

## Requirements

- Ensure that you have one of the following required operating systems:

  - Ubuntu 18.04-server

- Please follow [Intel SGX Installation Guide](https://download.01.org/intel-sgx/sgx-linux/2.11/docs/Intel_SGX_Installation_Guide_Linux_2.11_Open_Source.pdf) to install Intel SGX driver, Intel SGX SDK & PSW for Linux.

## Build and install the PAL of skeleton enclave runtime

Please follow the command to build skeleton from the latested source code on your system.

1. Install the dependencies

- protobuf-c

  - For source code build:
    Please refer to [this step](https://github.com/protobuf-c/protobuf-c#building) to install it on your platform. Note that `protobuf-c` must be 1.3 or higher.

- Binutils

  `Binutils` is a collection of tools for handling binary files. Please install it with the command:

    - For Ubuntu 18.04

    ```shell
    apt-get install -y binutils-dev
    ```

2. Build and install 

```shell
cd "${path_to_inclavare_containers}/rune/libenclave/internal/runtime/pal/skeleton"
make
cp liberpal-skeleton-v*.so /usr/lib
```

## Build skeleton docker image

Type the following commands to create a Dockerfile:

```shell
cd "${path_to_inclavare_containers}/rune/libenclave/internal/runtime/pal/skeleton"
cat >Dockerfile <<EOF
FROM ubuntu:18.04

RUN mkdir -p /run/rune
WORKDIR /run/rune

COPY encl.bin .
COPY encl.ss .
EOF
```

Then build the skeleton docker image with the command:

```shell
docker build . -t skeleton-enclave
```

## Deploy skeleton docker image

The following guide provides the steps to run skeleton with Docker and OCI Runtime `rune`.

- Please refer to [this guide](https://github.com/alibaba/inclavare-containers#rune) to build `rune` from scratch.

### Integrate OCI Runtime rune with Docker

Add the `rune` OCI runtime configuration in dockerd config file, e.g, `/etc/docker/daemon.json`, in your system.

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
> e.g. `sudo service docker restart` for Ubuntu

You can check whether `rune` is correctly picked as supported OCI runtime or not with

```shell
docker info | grep rune
Runtimes: rune runc
```

### Run skeleton docker image

Note that replace `${SKELETON_PAL_VERSION}` with the actual version number. Currently skeleton supports PAL API v1, v2 and v3.

```shell
docker run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-skeleton-v${SKELETON_PAL_VERSION}.so \
  -e ENCLAVE_RUNTIME_ARGS="debug" \
  -e ENCLAVE_RUNTIME_LOGLEVEL="info" \
  skeleton-enclave
```

where:
- @ENCLAVE\_TYPE: specify the type of enclave hardware to use, such as `intelSgx`.
- @ENCLAVE\_PATH: specify the path to enclave runtime to launch.
- @ENCLAVE\_ARGS: specify the specific arguments to enclave runtime, seperated by the comma.

---

# Developement

The following method to run skeleton bundle with `rune` is usually provided for developmemt purpose.

## Create skeleton docker image

Please refer to [this guide](#build-skeleton-docker-image) to build the skeleton docker image.

## Create skeleton bundle

In order to use `rune` you must have your docker image in the format of an OCI bundle. If you have Docker installed you can use its `export` method to acquire a root filesystem from an existing skeleton docker image.

```shell
# create the top most bundle directory
cd "$HOME/rune_workdir"
mkdir rune-container
cd rune-container

# create the rootfs directory
mkdir rootfs

# export skeleton image via Docker into the rootfs directory
docker export $(docker create skeleton-enclave) | sudo tar -C rootfs -xvf -
```

After a root filesystem is populated you just generate a spec in the format of a config.json file inside your bundle. `rune` provides a spec command which is similar to `runc` to generate a template file that you are then able to edit.

```shell
rune spec
```

To find features and documentation for fields in the spec please refer to the [specs](https://github.com/opencontainers/runtime-spec) repository.

In order to run the skeleton bundle with `rune`, you need to configure enclave runtime as following:

```json
  "annotations": {
      "enclave.type": "intelSgx",
      "enclave.runtime.path": "/usr/lib/liberpal-skeleton-v${SKELETON_PAL_VERSION}.so",
      "enclave.runtime.args": "debug",
      "enclave.runtime.loglevel": "info"
  }
```

where:
- @enclave.type: specify the type of enclave hardware to use, such as intelSgx.
- @enclave.runtime.path: specify the path to enclave runtime to launch.
- @enclave.runtime.args: specify the specific arguments to enclave runtime, seperated by the comma.
- @enclave.runtime.loglevel: specify the log level of the enclave runtime, such as "trace", "debug", "info", "warning", "error", "fatal", "panic", "off".

## Run skeleton OCI bundle

Assuming you have an OCI bundle from the previous step you can execute the container in this way.

```shell
cd "$HOME/rune_workdir/rune-container"
sudo rune run skeleton-enclave-container
```

---

# Features

Skeleton supports the following features right now:

- [Remote attestation](#remote-attestation)
- [Enclave metadata](#enclave-metadata)
- [Enclave instant launch](#enclave-instant-launch)
- [Enclave VM](#enclave-VM)

## Remote attestation

### `rune attest` command
`rune attest` command can get the local report or IAS report of enclave runtimes, you can refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/running_skeleton_with_rune_attest_command.md) to run skeleton with `rune attest` command.

Note that only liberpal-skeleton-v3.so supports `rune attest` command.

### TLS Server

You can refer to [this guide](intergrate_skeleton_with_enclave_tls.md) to run skeleton with tls server.

## Enclave metadata

User can predefine the expected value in enclave metadata area when using `sgxsign` tool on a machine with different hardware configuration against runtime. The signing behavior should be recorded and reproduced during runtime.

The options provided by `sgxsign` tool are as followed:

| Options                             | Function                                                                                               |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------|
| -N, --no-debugger                   | Prohibit debugger to read and write enclave data. The enclave debug is permitted by default.           |
| -D, --debug-enclave                 | Build a debug enclave. A product enclave is built by default.                                          |
| -s, --mmap-size value               | Launch an enclave with memory size equals to value (in-byte).                                          |
| -a, --attrs value                   | Launch an enclave with attributes equals to value (in hex).                                            |
| -A, --attrs-mask value              | Enforce the attributes value (in hex) specified by --attrs.                                            |
| -x, --xfrm value                    | Launch an enclave with xfrm equals to value (in hex).                                                  |
| -X, --xfrm-mask value               | Enforce the xfrm value (in hex) specified by --xfrm.                                                   |
| -n, --null\_dereference\_protection | Enable [Enclave NULL dereference protection](#enclave-null-dereference-protection). Disable by default.|
| -m, --mman\_min\_addr value         | Launch an enclave with mman\_min\_addr equals to value(hex).                                           |

Note:
- For SGX1 platforms, --no-debugger is not allowed unless the enclave is signed by a product enclave signing key authorized by Intel. This means your unauthorized enclave is not secured at all because the local admin can employ sgx-gdb to read and write any enclave data.

### Enclave NULL dereference protection

Skeleton enclave runtime implements NULL pointer dereference protection for the purpose of demonstration. This common protection mechanism can prevent potential confidential data leaks.

The potential attacker may re-map zero page to induce the buggy enclave to
read the zero page fed with malicious data, or write the confidential data
to zero page.

In order to prevent from this attack, skeleton enclave runtime implements
enclave NULL dereference protection for OOT and in-tree drivers. However,
OOT and in-tree drivers have different designs and implementations. This
also affects the behavior of enclave NULL dereference protection.

In order to enable this protection for OOT driver, the restriction from
mmapping must be disabled:

```shell
sudo sysctl -w vm.mmap_min_addr=0
```
in-tree driver doesn't have to do it.

FIXME: Current implementation assuems the build, signing and running stages
are on the same platform.

## Enclave instant launch

Enclave instant launch can completely eliminate the launch time of loading and measuring the enclave instance. Once an enclave is setup, it can be used by mapping enclave fd and enclave EPC address in other processes.

Enclave share mapping module is implemented including two parts: epm service used to store enclave in enclave pool and epm client used to consume enclave from epm service and produce enclave as well.

Enclave instant launch only support skeleton right now, it will support more enclave runtimes in the future.

### Run epm service

You can run epm service following with epm [README](https://github.com/alibaba/inclavare-containers/blob/master/epm/README.md).

```shell
sudo epm &
```

### Run epm client

#### Run skeleton with epm by docker image

According to previous steps about how to build [skeleton docker image](https://github.com/alibaba/inclavare-containers/tree/master/rune/libenclave/internal/runtime/pal/skeleton#build-skeleton-docker-image), you can get the image skeleton-enclave. Then type the following commands to run skeleton with epm:

```shell
docker run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-skeleton-v3.so \
  -e ENCLAVE_RUNTIME_ARGS="debug" \
  -e ENCLAVE_RUNTIME_LOGLEVEL="info" \
  skeleton-enclave
```

For users who don't want to use epm, please append "no-epm" as below:

```shell
docker run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-skeleton-v3.so \
  -e ENCLAVE_RUNTIME_ARGS="debug,no-epm" \
  -e ENCLAVE_RUNTIME_LOGLEVEL="info" \
  skeleton-enclave
```

#### Run skeleton with epm by OCI bundle

Assuming you have an OCI bundle according to previous steps, please add config into config.json as following:

```json
"annotations": {
	"enclave.type": "intelSgx",
	"enclave.runtime.path": "/usr/lib/liberpal-skeleton-v3.so",
	"enclave.runtime.args": "debug",
	"enclave.runtime.loglevel": "info"
}
```

For users who don't want to use epm, please append "no-epm" as below:

```json
"annotations": {
        "enclave.type": "intelSgx",
        "enclave.runtime.path": "/usr/lib/liberpal-skeleton-v3.so",
        "enclave.runtime.args": "debug,no-epm",
        "enclave.runtime.loglevel": "info"
}
```

```shell
cd "$HOME/rune_workdir/rune-container"
sudo rune run skeleton-enclave-container
```

## Enclave VM

Skeleton now can interact with [kvmtool](../kvmtool) to support enclave VM for demonstration. This is the first step to support a new form of enclave.

Skeleton implements enclave based on VM in two steps, `kvmtool` is a hypervisor running on KVM. By stripping the functions in kvmtool, it implements a high-level abstract library `libvmm`, which is a relatively common library implemented in C language. Then it connects to PAL API based on `libvmm` in skeleton environment.

At present, enclave VM based on kvmtool is only implemented in skeleton v2.

### Run skeleton with kvmtool

Assuming you have an OCI bundle according to previous steps, please add config into config.json as following:

```json
{
	"annotations": {
		"enclave.runtime.args": "debug backend-kvm kvm-kernel=/path/to/bzImage kvm-rootfs=/ kvm-init=/bin/bash",
		"enclave.runtime.path": "/path/to/liberpal-skeleton-v2.so",
		"enclave.runtime.loglevel": "info"
	},
	"linux": {
		"devices": [
			{
				"path": "/dev/kvm",
				"type": "c",
				"major": 10,
				"minor": 232,
				"fileMode": 438,
				"uid": 0,
				"gid": 0
			},
			{
				"path": "/dev/net/tun",
				"type": "c",
				"major": 10,
				"minor": 200,
				"fileMode": 438,
				"uid": 0,
				"gid": 0
			}
		],
		"resources": {
			"devices": [
				{
					"allow": true
				}
			]
		},
	}
}
```

Please modify the above device information according to the actual situation, such as fileMode, minor number, etc.

The configuration of `kvm-rootfs` takes bundle as an absolute address of rootfs, the bundle is specified in the parameters of rune.

```shell
cp inclavare-containers/pal/skeleton/encl.{bin,ss} bundle/run/rune
rune --debug run -b bundle test
```
