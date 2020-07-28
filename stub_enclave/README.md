# Build Stub Enclave
``` shell
cd "${path_to_inclavare_containers}/rune/libenclave/internal/runtime/pal/stub_enclave"
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
  
RUN mkdir -p /run/rune/sgxsdk
WORKDIR /run/rune

COPY lib                        /lib
COPY liberpal-sgxsdk.so         .
COPY Wolfssl_Enclave.signed.so  sgxsdk

RUN ldconfig
```

``` shell
docker build -t ${stub-enclave-image} .
```

# run stub-enclave images with rune
``` shell
sudo docker run -it --rm --runtime=rune -e ENCLAVE_TYPE=intelSgx \
		-e ENCLAVE_RUNTIME_PATH=/usr/lib/liberpal-sgxsdk.so \
		-e ENCLAVE_RUNTIME_ARGS=sgxsdk ${stub-enclave-image}
```
