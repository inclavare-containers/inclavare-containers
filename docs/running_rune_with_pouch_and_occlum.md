# Running rune with pouch and Occlum

This user guide provides the steps to run rune with pouch and Occlum.

# Requirements

Please refer to [this guide](https://github.com/alibaba/pouch/blob/master/INSTALLATION.md) to install pouch and refer to [this guide](https://github.com/alibaba/inclavare-containers#pouchd) to configure the runtime of pouchd.

# Running Occlum container image

Please refer to [this guide](https://github.com/occlum/occlum/blob/master/docs/rune_quick_start.md) to build your Occlum container image. Then run pouch with Occlum container images refer to

```shell
pouch run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/opt/occlum/build/lib/libocclum-pal.so \
  -e ENCLAVE_RUNTIME_ARGS=occlum_instance \
  occlum-app
```

In addition, pouch supports to configure `annotation` options to run container image. You can run pouch with annotations instead of environment variables.

```shell
pouch run -it --rm --runtime=rune \
  --annotation "enclave.type=intelSgx" \
  --annotation "enclave.runtime.path=/opt/occlum/build/lib/libocclum-pal.so" \
  --annotation "enclave.runtime.args=occlum_instance" \
  occlum-app
```
