# containerd-shim-rune-v2

containerd-shim-rune-v2 is a shim for Inclavare Containers(runE).

## Introduction
![shim-rune](docs/images/shim-rune.png)

## Carrier Framework
Carrier is a abstract framework to build an enclave for the specified enclave runtime (Occlum、Graphene ..) .

![shim-carrier](docs/images/shim-carrier.png)

## Signature Framework

![shim-signature](docs/images/shim-signature.png)

## Build requirements

Go 1.13.x or above.

## How to build and install

### Step 1: Build and install shim binary.
```bash
mkdir -p $GOPATH/src/github.com/alibaba
cd $GOPATH/src/github.com/alibaba 
git clone https://github.com/alibaba/inclavare-containers.git

cd shim
GOOS=linux make binaries
make install
ls -l /usr/local/bin/containerd-shim-rune-v2
```

### Step 2: Configuration

The Configuration file of Inclavare Containers MUST BE placed into `/etc/inclavare-containers/config.toml`

```toml
log_level = "debug" # "debug" "info" "warn" "error"
sgx_tool_sign = "/opt/intel/sgxsdk/bin/x64/sgx_sign"

[containerd]
    socket = "/run/containerd/containerd.sock"

[enclave_runtime]

    [enclave_runtime.occlum]
        build_image = "docker.io/occlum/occlum:0.15.1-ubuntu18.04"
        enclave_runtime_path = "/opt/occlum/build/lib/libocclum-pal.so.0.15.1"
    [enclave_runtime.graphene]

```

Modify containerd configuration file(/etc/containerd/config.toml) and add runtimes rune into it.

```toml
#...
      [plugins.cri.containerd.runtimes.rune]
        runtime_type = "io.containerd.rune.v2"
#...
```

Add RuntimeClass rune into your kubernetes cluster.
```bash
cat <<EOF | kubectl create -f -
apiVersion: node.k8s.io/v1beta1
kind: RuntimeClass
metadata:
  name: rune
handler: rune
scheduling:
  nodeSelector:
    # Your rune worker labels.
    #alibabacloud.com/container-runtime: rune
EOF
```

## Run HelloWorld in kubernetes
```bash
cat <<EOF | kubectl create -f -
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: helloworld-in-tee
  name: helloworld-in-tee
spec:
  runtimeClassName: rune
  containers:
  - command:
    - /bin/hello_world
    env:
    - name: RUNE_CARRIER
      value: occlum
    image: registry.cn-shanghai.aliyuncs.com/larus-test/hello-world:v2
    imagePullPolicy: IfNotPresent
    name: helloworld
    workingDir: /run/rune
EOF
```
