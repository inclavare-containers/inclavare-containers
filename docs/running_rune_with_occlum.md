# Quick Start: running rune with Occlum
[rune](https://github.com/alibaba/inclavare-containers) is a new OCI runtime used to run trusted applications in containers with the hardware-assisted enclave technology.

## Requirements
- Install [Intel SGX driver for Linux](https://github.com/intel/linux-sgx-driver#build-and-install-the-intelr-sgx-driver), required by Intel SGX SDK && PSW.
- Install [enable_rdfsbase kernel module](https://github.com/occlum/enable_rdfsbase#how-to-build), allowing to use `rdfsbase` -family instructions in Occlum.
- Assume the host system is CentOS 7.5.
- You can also launch a CentOS 7.5 container as your host system with the following command:
  ```shell
  docker run -it --privileged --device /dev/isgx centos:7.5.1804
  ```
  If so, you need to run **another docker daemon** inside this CentOS 7.5 container. Please refer to [this guide](https://docs.docker.com/engine/install/centos) to install docker daemon, and type the following command to start dockerd.
  ```shell
  dockerd -b docker0 --storage-driver=vfs &
  ```

---

## Build Occlum application container image
### Download Occlum SDK container image
```shell
mkdir "$HOME/rune_workdir"
docker run -it --privileged --device /dev/isgx \
  -v "$HOME/rune_workdir":/root/rune_workdir \
  occlum/occlum:0.14.0-centos7.5
```

### Prepare the materials
Before Occlum build, execute the following command to set your Occlum instance name:

```shell
export OCCLUM_INSTANCE_DIR=occlum-app
```

[This guide](https://github.com/occlum/occlum#hello-occlum) can help you to create your first occlum build.

Assuming "hello world" demo program is built, execute the following commands in Occlum SDK container:

```shell
cp -a ${OCCLUM_INSTANCE_DIR} /root/rune_workdir
```

### Prepare Occlum application image
Now you can build your occlum application image in the $HOME/rune_workdir directory of your host system.

Type the following commands to create a `Dockerfile`:
``` Dockerfile
cd "$HOME/rune_workdir"
cat >Dockerfile <<EOF
FROM centos:7.5.1804

ENV OCCLUM_INSTANCE_DIR=occlum-app
RUN mkdir -p /run/rune/${OCCLUM_INSTANCE_DIR}
WORKDIR /run/rune

COPY ${OCCLUM_INSTANCE_DIR} ${OCCLUM_INSTANCE_DIR}
COPY ${OCCLUM_INSTANCE_DIR}/build/lib/libocclum-pal.so /usr/lib/liberpal-occlum.so

ENTRYPOINT ["/bin/hello_world"]
EOF
```

and then build it with the command:
```shell
docker build . -t ${Occlum_application_image}
```

---

## Install Inclavare Containers binary
Download the binary release from [here](https://github.com/alibaba/inclavare-containers/releases/).

### Install `sgx_linux_x64_sdk_2.9.101.2.bin`
Type the following commands to install `sgx_linux_x64_sdk_2.9.101.2.bin` on your host system.
```shell
yum install -y make
echo -e "no\n/opt/intel\n" | ./sgx_linux_x64_sdk_2.9.101.2.bin
```

### Install `sgx_linux_x64_psw_2.9.101.2.bin` 
Type the following commands to install `sgx_linux_x64_psw_2.9.101.2.bin` on your host system.
```shell
yum install -y https://cbs.centos.org/kojifiles/packages/protobuf/3.6.1/4.el7/x86_64/protobuf-3.6.1-4.el7.x86_64.rpm
./sgx_linux_x64_psw_2.9.101.2.bin
cd /opt/intel/sgxpsw/aesm
export LD_LIBRARY_PATH=$PWD
export AESM_PATH=$PWD
/opt/intel/sgxpsw/aesm/aesm_service
```

### Install rune and liberpal-occlum.so
```shell
cp ./rune /usr/local/sbin
cp ./liberpal-occlum.so /usr/lib
```

---

## Config OCI Runtimes
Add the `rune` OCI runtime configuration in dockerd config file, e.g, `/etc/docker/daemon.json`, on your system.

```JSON
{
	"runtimes": {
		"rune": {
			"path": "/usr/local/sbin/rune",
			"runtimeArgs": []
		}
	}
}
```

then restart dockerd on your system.

You can check whether `rune` is correctly added to OCI runtime or not with
```shell
docker info | grep rune
Runtimes: rune runc
```

---

## Run Occlum application image using rune
You need to specify a set of parameters to `docker run` in order to use `rune`, e.g,

```shell
export OCCLUM_INSTANCE_DIR=occlum-app
yum install -y libseccomp
docker run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-occlum.so \
  -e ENCLAVE_RUNTIME_ARGS=${OCCLUM_INSTANCE_DIR} \
  ${Occlum_application_image}
```

where:
- @ENCLAVE_TYPE: specify the type of enclave hardware to use, such as `intelSgx`.
- @ENCLAVE_PATH: specify the path to enclave runtime to launch.
- @ENCLAVE_ARGS: specify the specific arguments to enclave runtime, separated by the comma.
