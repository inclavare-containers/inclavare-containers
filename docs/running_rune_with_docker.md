# Quick Start: Running rune with Docker
## Build and install rune
`rune` is a CLI tool for spawning and running enclaves in containers according to the OCI specification.

Please refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/README.md#rune) to build `rune` from scratch.

---

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

---

## Running Docker using rune
You need to specify a set of parameters to `docker run` in order to use `rune`, e.g,

``` shell
docker run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/run/rune/liberpal-skeleton.so \
  -e ENCLAVE_RUNTIME_ARGS=skeleton,debug \
  $image
```

where:
- @runtime: choose the runtime (`rune`, `runc` or others) to use for this container.
- @ENCLAVE_TYPE: specify the type of enclave hardware to use, such as `intelSgx`.
- @ENCLAVE_PATH: specify the path to enclave runtime to launch.
- @ENCLAVE_ARGS: specify the specific arguments to enclave runtime, seperated by the comma.

Note that the skeleton is a sample enclave runtime. Please refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md) to run skeleton with `rune`. In addition, refer to [this guide]() to run more useful Occlum library OS.
