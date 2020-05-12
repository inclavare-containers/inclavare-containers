The files in this directory are used to implement a skeleton enclave runtime,
in order to help to write your own enclave runtime.

# Build liberpal-skeleton.so
```shell
cd "$GOPATH/src/github.com/alibaba/inclavare-containers/rune"
make all
```

# Build skeleton docker image
```shell
cd "$GOPATH/src/github.com/alibaba/inclavare-containers/rune/libenclave/internal/runtime/pal/skeleton"
cat >Dockerfile <<EOF
FROM centos:7.2.1511

RUN mkdir -p /run/rune
WORKDIR /run/rune

RUN yum install -y libseccomp-devel
COPY liberpal-skeleton.so .

RUN ldconfig
EOF
docker build . -t liberpal-skeleton
```

# Run skeleton docker image
```shell
docker run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/run/rune/liberpal-skeleton.so \
  -e ENCLAVE_RUNTIME_ARGS="skeleton,debug" \
  liberpal-skeleton
```
