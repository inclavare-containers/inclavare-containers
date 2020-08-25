# Configure SGX RA settings
``` shell
export SPID=<hex string>
export EPID_SUBSCRIPTION_KEY=<hex string>
export QUOTE_TYPE=<SGX_LINKABLE_SIGNATURE | SGX_UNLINKABLE_SIGNATURE>
```

# Build Stub Enclave
``` shell
cd "${path_to_inclavare_containers}/stub-enclave"
make
sudo make install
```

# Build Docker images
## Prepare the materials
``` shell
mkdir lib
cp /usr/lib/x86_64-linux-gnu/libsgx_urts.so lib
cp /usr/lib/x86_64-linux-gnu/libsgx_uae_service.so lib
cp /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1 lib
cp /usr/lib/x86_64-linux-gnu/libprotobuf.so.10 lib
cp /lib/x86_64-linux-gnu/libseccomp.so.2 lib
```

## Dockerfile
``` shell
FROM ubuntu:18.04
  
RUN mkdir -p /run/rune/stub-enclave
WORKDIR /run/rune

COPY lib                        /lib
COPY liberpal-stub.so         .
COPY Wolfssl_Enclave.signed.so  stub-enclave

RUN ldconfig
```

``` shell
docker build -t ${stub-enclave-image} .
```

# run stub-enclave images with rune
``` shell
docker run -it --rm --runtime=rune -e ENCLAVE_TYPE=intelSgx \
	-e ENCLAVE_RUNTIME_PATH=/lib/liberpal-stub.so \
	-e ENCLAVE_RUNTIME_ARGS=stub-enclave ${stub-enclave-image}
```
