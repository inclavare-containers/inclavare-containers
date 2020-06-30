The files in this directory are used to implement a skeleton enclave runtime,
in order to help to write your own enclave runtime.

# Install runectl
Refer to [this guide](https://github.com/alibaba/inclavare-containers/tree/master/runectl)

# Build liberpal-skeleton.so
```shell
cd "${path_to_inclavare_containers}/rune/libenclave/internal/runtime/pal/skeleton"
make
cp liberpal-skeletion.so /usr/lib
```

# Build skeleton docker image
```shell
cd "${path_to_inclavare_containers}/rune/libenclave/internal/runtime/pal/skeleton"
cat >Dockerfile <<EOF
FROM centos:7.5.1804

RUN mkdir -p /run/rune
WORKDIR /run/rune

COPY encl.bin .
COPY encl.elf .
COPY encl.ss .
COPY encl.token .
EOF
docker build . -t liberpal-skeleton
```

# Build and install rune
`rune` is a CLI tool for spawning and running enclaves in containers according to the OCI specification.

Please refer to [this guide](https://github.com/alibaba/inclavare-containers#rune) to build `rune` from scratch.

# Run skeleton docker image
## Configure Docker runtimes
Add the `rune` OCI runtime configuration in dockerd config file (`/etc/docker/daemon.json`) in your system.

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

## Run skeleton docker image with rune
```shell
docker run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-skeleton.so \
  -e ENCLAVE_RUNTIME_ARGS="debug" \
  liberpal-skeleton
```

where:
- @runtime: choose the runtime (`rune`, `runc` or others) to use for this container.
- @ENCLAVE_TYPE: specify the type of enclave hardware to use, such as `intelSgx`.
- @ENCLAVE_PATH: specify the path to enclave runtime to launch.
- @ENCLAVE_ARGS: specify the specific arguments to enclave runtime, seperated by the comma.

# Run skeleton OCI bundle
## Create skeleton bundle
In order to use `rune` you must have your container in the format of an OCI bundle. If you have Docker installed you can use its `export` method to acquire a root filesystem from an existing skeleton Docker container.

``` shell
# create the top most bundle directory
cd "$HOME/rune_workdir"
mkdir rune-container
cd rune-container

# create the rootfs directory
mkdir rootfs

# export skeleton image via Docker into the rootfs directory
docker export $(docker create liberpal-skeleton) | sudo tar -C rootfs -xvf -
```

After a root filesystem is populated you just generate a spec in the format of a config.json file inside your bundle. `rune` provides a spec command which is similar to `runc` to generate a template file that you are then able to edit.

``` shell
rune spec
```

To find features and documentation for fields in the spec please refer to the [specs](https://github.com/opencontainers/runtime-spec) repository.

In order to run the skeleton bundle with `rune`, you need to configure enclave runtime as following:
``` json
  "annotations": {
      "enclave.type": "intelSgx",
      "enclave.runtime.path": "/usr/lib/liberpal-skeleton.so",
      "enclave.runtime.args": "debug"
  }
```

where:

- @enclave.type: specify the type of enclave hardware to use, such as intelSgx.
- @enclave.runtime.path: specify the path to enclave runtime to launch.
- @enclave.runtime.args: specify the specific arguments to enclave runtime, seperated by the comma.
---

## Run skeleton application
Assuming you have an OCI bundle from the previous step you can execute the container in this way.

``` shell
cd "$HOME/rune_workdir/rune-container"
sudo rune run "liberpal-skeleton"
```
