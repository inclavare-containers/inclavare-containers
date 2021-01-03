# Running inclavare-containers with pouch and Occlum

This user guide provides the steps to run inclavare-containers with pouch and Occlum.

# Requirements
## pouch

Please refer to [this guide](https://github.com/alibaba/pouch/blob/master/INSTALLATION.md) to install pouch and refer to [this guide](https://github.com/alibaba/inclavare-containers#pouchd) to configure the runtime of pouchd.

## rune

Please refer to [this guide](https://github.com/alibaba/inclavare-containers/tree/master/rune#building) to install `rune`.

## shim-rune

Please refer to [this guide](https://github.com/alibaba/inclavare-containers/tree/master/shim#step-1-build-and-install-shim-binary) to install `shim-rune` and refer to [this guide](https://github.com/alibaba/inclavare-containers/tree/master/shim#step-2-configuration) to configure `shim-rune`.

# Running Occlum container image

Please refer to [this guide](https://github.com/occlum/occlum/blob/master/docs/rune_quick_start.md) to build your Occlum container image. 

Use the environment variable OCCLUM_RELEASE_ENCLAVE to specify your enclave type
- OCCLUM_RELEASE_ENCLAVE=0: debug enclave
- OCCLUM_RELEASE_ENCLAVE=1: product enclave

Then run pouch with Occlum container images refer to

```shell
pouch run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/opt/occlum/build/lib/libocclum-pal.so \
  -e ENCLAVE_RUNTIME_ARGS=occlum_instance \
  -e ENCLAVE_RUNTIME_LOGLEVEL=info \
  -e OCCLUM_RELEASE_ENCLAVE=0 \
  occlum-app
```

In addition, pouch supports to configure `annotation` options to run container image. You can run pouch with annotations instead of environment variables.

```shell
pouch run -it --rm --runtime=rune \
  --annotation "enclave.type=intelSgx" \
  --annotation "enclave.runtime.path=/opt/occlum/build/lib/libocclum-pal.so" \
  --annotation "enclave.runtime.args=occlum_instance" \
  --annotation "enclave.runtime.loglevel=info" \
  -e OCCLUM_RELEASE_ENCLAVE=0 \
  occlum-app
```
