# Quick Start: Running rune with Occlum bundle

## Build and install rune
`rune` is a CLI tool for spawning and running enclaves in containers according to the OCI specification.

Please refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/README.md#rune) to build `rune` from scratch.

---

## Build Occlum application container image
Please refer to [this guide](https://github.com/alibaba/inclavare-containers/blob/master/docs/running_rune_with_occlum.md) to build the Occlum application container image.

## Create Occlum application bundle
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
docker export $(docker create ${Occlum_application_image}) | sudo tar -C rootfs -xvf -
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
      "enclave.runtime.path": "/opt/occlum/build/lib/libocclum-pal.so.0.15.1",
      "enclave.runtime.args": "./"
  }
```

where:
- @enclave.type: specify the type of enclave hardware to use, such as `intelSgx`.
- @enclave.runtime.path: specify the path to enclave runtime to launch. For an Occlum application, you need to specify the path to `libocclum-pal.so`.
- @enclave.runtime.args: specify the specific arguments to enclave runtime, separated by the comma.

---

## Run Occlum application
Assuming you have an OCI bundle from the previous step you can execute the container in this way.

```shell
cd "$HOME/rune_workdir/rune-container"
sudo rune run ${Occlum_application_container_name}
```
