The files in this directory are used to implement a skeleton enclave runtime,
in order to help to write your own enclave runtime.

# Install runectl
Refer to [this guide](https://github.com/alibaba/inclavare-containers/tree/master/runectl)

# Build liberpal-skeleton.so
```shell
cd "${path_to_inclavare_containers}/rune/libenclave/internal/runtime/pal/skeleton"
make
```

# Build skeleton docker image
```shell
cd "${path_to_inclavare_containers}/rune/libenclave/internal/runtime/pal/skeleton"
cat >Dockerfile <<EOF
FROM centos:7.2.1511

RUN mkdir -p /run/rune
WORKDIR /run/rune

RUN yum install -y libseccomp-devel
COPY liberpal-skeleton.so .
COPY encl.bin .
COPY encl.elf .
COPY encl.ss .
COPY encl.token .

RUN ldconfig
EOF
docker build . -t liberpal-skeleton
```

# Run skeleton docker image
## Build and install rune
`rune` is a CLI tool for spawning and running enclaves in containers according to the OCI specification.

Please refer to [this guide](https://github.com/alibaba/inclavare-containers#rune) to build `rune` from scratch.

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
  -e ENCLAVE_RUNTIME_PATH=/run/rune/liberpal-skeleton.so \
  -e ENCLAVE_RUNTIME_ARGS="debug" \
  liberpal-skeleton
```
