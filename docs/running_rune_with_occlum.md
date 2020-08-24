# Quick Start: running rune with Occlum
[rune](https://github.com/alibaba/inclavare-containers) is a new OCI runtime used to run trusted applications in containers with the hardware-assisted enclave technology.

## Requirements
- Install Intel SGX driver for Linux by following [Intel SGX Installation Guide](https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Installation_Guide_Linux_2.9.1_Open_Source.pdf), required by Intel SGX SDK && PSW.
- Install [enable_rdfsbase kernel module](https://github.com/occlum/enable_rdfsbase#how-to-build), allowing to use `rdfsbase` -family instructions in Occlum.
- Ensure that you have one of the following required operating systems:
  - CenOS 8.1
  - Ubuntu 18.04-server

  Note: You may also choose to launch a container corresponding to above operating systems.
  ```shell
  docker run -it --privileged --device /dev/isgx centos:8.1.1911
  ```
  or
  ```shell
  docker run -it --privileged --device /dev/isgx ubuntu:18.04
  ```
  If so, you need to run **another docker daemon** inside your container. Please refer to [this guide](https://docs.docker.com/engine/install) to install docker daemon. In CentOS 8.1 container, type the following command to start dockerd.
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
  occlum/occlum:0.15.1-centos8.1
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
cd "$HOME/rune_workdir/${OCCLUM_INSTANCE_DIR}"
cat >Dockerfile <<EOF
FROM centos:8.1.1911

RUN mkdir -p /run/rune
WORKDIR /run/rune

COPY Occlum.json ./
COPY build ./build
COPY image ./image
COPY run ./run

ENTRYPOINT ["/bin/hello_world"]
EOF
```

and then build it with the command:
```shell
docker build . -t ${Occlum_application_image}
```

---

## Install SGX SDK and SGX PSW
Please follow [Intel SGX Installation Guide](https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Installation_Guide_Linux_2.9.1_Open_Source.pdf) to install SGX SDK and SGX PSW.

In additon, UAE service libraries are needed but may not installed together with SGX PSW if SGX PSW installer is used. Go to SGX RPM local repo and run:

```shell
rpm -i libsgx-uae-service-2.9.101.2-1.el8.x86_64.rpm
```

## Install rune and occlum-pal
Download the package from [here](https://github.com/alibaba/inclavare-containers/releases/).

- On CentOS 8.1:
```shell
yum install -y libseccomp
rpm -ivh rune-0.4.0-1.el8.x86_64.rpm
rpm -ivh occlum-pal-0.15.1-1.el8.x86_64.rpm
```
- On Ubuntu 18.04-server:
```shell
dpkg -i rune_0.4.0-1_amd64.deb
dpkg -i occlum-pal_0.15.1_amd64.deb
```

---

## Config OCI Runtimes
Add the `rune` OCI runtime configuration in dockerd config file, e.g, `/etc/docker/daemon.json`, on your system.

```JSON
{
	"runtimes": {
		"rune": {
			"path": "/usr/bin/rune",
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
docker run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/opt/occlum/build/lib/libocclum-pal.so.0.15.1 \
  -e ENCLAVE_RUNTIME_ARGS=./ \
  ${Occlum_application_image}
```

where:
- @ENCLAVE_TYPE: specify the type of enclave hardware to use, such as `intelSgx`.
- @ENCLAVE_PATH: specify the path to enclave runtime to launch.
- @ENCLAVE_ARGS: specify the specific arguments to enclave runtime, separated by the comma.
