# Quick Start: rune on Occlum

[rune](https://github.com/alibaba/inclavare-containers) is a set of tools for running trusted applications in containers with the hardware-assisted enclave technology.

## Hardware requirements
- Install [Intel SGX driver for Linux](https://github.com/intel/linux-sgx-driver#build-and-install-the-intelr-sgx-driver), required by Intel SGX SDK && PSW.
- Install [enable_rdfsbase kernel module](https://github.com/occlum/enable_rdfsbase#how-to-build), allowing to use `rdfsbase` -family instructions in Occlum.

---

## Build Occlum application Docker image
### Download Occlum sdk image
``` shell
docker pull occlum/occlum:0.13.0-centos7.5
docker run -it --privileged --device /dev/isgx \
  occlum/occlum:0.13.0-centos7.5
```

### Prepare the materials
Before Occlum build, execute the following command to set your Occlum instance dir:
``` shell
export OCCLUM_INSTANCE_DIR=occlum-app
```
You can build a "hello world" demo application or your own product with an [Occlum CentOS Docker image](https://hub.docker.com/r/occlum/occlum/tags).

[This guide](https://github.com/occlum/occlum#hello-occlum) can help you to create your first occlum build.

After Occlum build, execute the following commands in Occlum sdk container environment:

``` shell
yum install -y libseccomp-devel
mkdir /root/rune_workdir
cp -a ${OCCLUM_INSTANCE_DIR} /root/rune_workdir
cd /root/rune_workdir
cp ${OCCLUM_INSTANCE_DIR}/build/lib/libocclum-pal.so /usr/lib/liberpal-occlum.so
```

### Build occlum application image
Now you can build your occlum application image in the same Occlum sdk container environment.

You need to [download docker](https://docs.docker.com/engine/install/centos/) in the Occlum sdk container environment. And type the following command to start your docker service.
``` shell
dockerd -b docker0 --storage-driver=vfs &
```

Type the following commands to create a `Dockerfile`:
``` Dockerfile
cat >Dockerfile <<EOF
FROM centos:7.5.1804

ENV OCCLUM_INSTANCE_DIR=occlum-app
RUN mkdir -p /run/rune/${OCCLUM_INSTANCE_DIR}
WORKDIR /run/rune

COPY ${OCCLUM_INSTANCE_DIR} ${OCCLUM_INSTANCE_DIR}

ENTRYPOINT ["/bin/hello_world"]
EOF
```

and then build it with the command:
```shell
docker build . -t ${Occlum_application_image}
```

---

## Install rune binarys 
You can download rune centos binarys from 0.2.0 release, it includes
- `rune` : is a set of tools for running trusted applications in containers with the hardware-assisted enclave technology. You can install `rune` in `/usr/local/sbin` on your centos system.
- `liberpal-occlum.so` : is the path to occlum to launch. you can install it on `/usr/lib`  on your centos system.
- `sgx_linux_x64_sdk_2.9.101.2.bin` : is a [SGX SDK](https://github.com/intel/linux-sgx#install-the-intelr-sgx-sdk-1) binary. 
- `sgx_linux_x64_psw_2.9.101.2.bin` : is a [SGX PSW](https://github.com/intel/linux-sgx#install-the-intelr-sgx-psw) binary.

### Install `sgx_linux_x64_sdk_2.9.101.2.bin`
Type the following commands to Install `sgx_linux_x64_sdk_2.9.101.2.bin` on your centos system.
``` shell
yum install -y make
mkdir -p /opt/intel
mv sgx_linux_x64_sdk_2.9.101.2.bin /opt/intel
cd /opt/intel
yes yes | ./sgx_linux_x64_sdk_2.9.101.2.bin
```

### Install `sgx_linux_x64_psw_2.9.101.2.bin` 
Type the following commands to Install `sgx_linux_x64_psw_2.9.101.2.bin` on your centos system.
``` shell
yum install -y https://cbs.centos.org/kojifiles/packages/protobuf/3.6.1/4.el7/x86_64/protobuf-3.6.1-4.el7.x86_64.rpm
mv sgx_linux_x64_psw_2.9.101.2.bin /opt/intel
cd /opt/intel
./sgx_linux_x64_psw_2.9.101.2.bin
source /opt/intel/sgxsdk/environment
LD_LIBRARY_PATH="/opt/intel/sgxpsw/aesm:$LD_LIBRARY_PATH" 
/opt/intel/sgxpsw/aesm/aesm_service
```

---

## Config Docker Runtimes
Add the `rune` OCI runtime configuration in dockerd config file (`/etc/docker/daemon.json`) on your system.

``` JSON
{
	"runtimes": {
		"rune": {
			"path": "/usr/local/sbin/rune",
			"runtimeArgs": []
		}
	}
}
```

then restart docker service on your system.
> e.g. `sudo systemctl restart docker` for CentOS, or `sudo service docker restart` for Ubuntu

You can check whether `rune` is correctly added to container runtime or not with
``` shell
sudo docker info | grep rune
Runtimes: rune runc
```

---

## Run Occlum application image using rune
You need to specify a set of parameters to `docker run` in order to use `rune`, e.g,

``` shell
docker run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-occlum.so \
  -e ENCLAVE_RUNTIME_ARGS=${OCCLUM_INSTANCE_DIR} \
  ${Occlum_application_image}
```

where:
- @runtime: choose the runtime (`rune`, `runc`, or others) to use for this container.
- @ENCLAVE_TYPE: specify the type of enclave hardware to use, such as `intelSgx`.
- @ENCLAVE_PATH: specify the path to enclave runtime to launch. For an Occlum application, you need to specify the path of `liberpal-occlum.so` which is a soft link to `libocclum-pal.so` of your Occlum instance dir (`OCCLUM_INSTANCE_DIR`).
- @ENCLAVE_ARGS: specify the specific arguments to enclave runtime, separated by the comma. For an Occlum application, you need to specify the name of your Occlum instance dir (`OCCLUM_INSTANCE_DIR`) in this parameter.
