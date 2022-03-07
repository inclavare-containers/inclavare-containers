The files in this directory are used to implement a nitro enclave runtime in order to help to write your own enclave runtime. For now just implement the pal interface for nitro enclave to run the sample enclave image file.

Note that this code base is inspired by [Sample flow of using the ioctl interface provided by the Nitro Enclaves (NE) kernel driver](https://github.com/torvalds/linux/blob/master/samples/nitro_enclaves/ne_ioctl_sample.c).

---

# Run nitro enclave with OCI bundle

## Create EC2 instance with Enclave enable

Refer to [Amazon EC2 instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Instances.html) to create a `EC2` instance which need to enable Enclave. Note that the limitation:
- virtualized Nitro-based instances with at least 4 vCPUs, except t3, t3a, t4g, a1, c6g, c6gd, m6g, m6gd, r6g, and r6gd.
- Parent instance and Enclave both are linux operating systems.

## Build nitro enclave environment

Refer to [Getting started: Hello enclave](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html) to build a `nitro enclave` environment in parent instance.

## Build and install rune

Please refer to [this guide](https://github.com/alibaba/inclavare-containers#rune) to build `rune` from scratch.

## Build and install rune pal library

```shell
cd inclavare-containers/rune/libenclave/internal/runtime/pal/nitro_enclaves
make
cp libpal_ne.so /usr/lib64/libpal_ne.so
```

## Configure OCI runtime

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

## Create eif bundle

In order to use `rune` you must have your container image in the format of an OCI bundle. If you have Docker installed you can use its `export` method to acquire a root filesystem from an existing nitro enclave  Docker container image.

```shell
# create the top most bundle directory
cd "$HOME/rune_workdir"
mkdir rune-container
cd rune-container

# create the rootfs directory
mkdir rootfs

# export hello image which build in [Getting started: Hello enclave](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html) via Docker into the rootfs directory
docker export $(docker create hello) | sudo tar -C rootfs -xvf -
```

After a root filesystem is populated you just generate a spec in the format of a config.json file inside your bundle. `rune` provides a spec command which is similar to `runc` to generate a template file that you are then able to edit.

```shell
rune spec
```

To find features and documentation for fields in the spec please refer to the [specs](https://github.com/opencontainers/runtime-spec) repository.

In order to run the nitro enclave bundle with `rune`, you need to configure enclave runtime as following:
```json
  "annotations": {
      "enclave.type": "AwsNitroEnclaves",
      "enclave.runtime.path": "/usr/lib64/libpal_ne.so",
      "enclave.runtime.args": "image=/root/hello.eif memory=256 vcpus=2"
  }
```

where:
- @enclave.type: specify the type of enclave hardware to use, such as intelSgx.
- @enclave.runtime.path: specify the path to enclave runtime to launch.
- @enclave.runtime.args: specify the specific arguments to enclave runtime, seperated by the comma.

## Run nitro enclave

Assuming you have an OCI bundle from the previous step you can execute the container in this way.

```shell
cd "$HOME/rune_workdir/rune-container"
sudo rune run hello-nitro-enclave-container
```
