---
title: "在集群里开发和部署一个 “Hello world”的 Enclave 容器"
description: "本指南将介绍如何在Kubernetes集群中开发和部署“ Hello World”容器"
github: "https://github.com/alibaba/inclavare-containers"
projects: [
  {name: "Inclavare Containers", link: "https://github.com/alibaba/inclavare-containers"}, 
]
---

该文档演示了如何基于 Occlum SDK 容器开发“Hello World”应用，构建“Hello World”镜像，并在 Kubernetes 集群中部署“Hello World”Enclave 容器。



## 准备工作

- 准备一个有硬件支持 Intel SGX 的 Kubernetes 机密计算集群。您可参考文档 [《创建 Inclavare-Containers 运行时的 Kubernetes 机密计算集群》](/guides/create-k8s-inclavare-containers/) 创建集群
- 确保操作系统是下面列表的一种：

    - CentOS 8.1 64位
    - Ubuntu 18.04 server 64位

## 目标

- 在 Occlum SDK 容器中开发 “Hello World”应用；
- 在 Occlum SDK 容器中构建 “Hello World”镜像；
- 在 Kubernetes 集群中创建 Pod，并在 Enclave 容器内运行“Hello World”应用”。

## 执行步骤

### 1. 基于 Occlum SDK 镜像创建 Pod

Occlum 是一个基于 Intel SGX 的内存安全、多线程的 LibOS，在不改动或改动很少代码的情况下就能让应用运行在 Enclave 中。

Intel SGX SDK 只支持 C、C++ 的应用，Occlum 再此基础上支持了更多语言 Runtime，目前支持的开发语言有：  C、C++、Rust、Golang、OpenJDK11 和 Dragonwell。

为了方便用户使用 Occlum 技术，Occlum 每个版本中同时会发布不同操作系统的 Occlum SDK 镜像，镜像内有开箱即用的 Occlum 的开发环境以及不同开发语言的样例工程。

我们也建议在 Occlum SDK 容器里开发和构建可信应用。可以在 [Docker Hub](https://hub.docker.com/r/occlum/occlum/tags) 中选择合适的版本。

- **步骤1：创建用于开发应用的 Pod**

执行以下命令创建开发应用的 Pod，该 Pod 用的 Occlum SDK 镜像版本是 `docker.io/occlum/occlum:0.14.0-centos7.5` ，同时把字段 `securityContext.privileged` 设置为 `true` ，用以在容器内构建和推送 docker 镜像。

```
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: occlum-app-builder
  name: occlum-app-builder
  namespace: default
spec:
  hostNetwork: true
  containers:
  - command:
    - sleep
    - infinity
    image: docker.io/occlum/occlum:0.14.0-centos7.5
    imagePullPolicy: IfNotPresent
    securityContext:
      privileged: true
    name: occlum-app-builder
EOF
```

- **步骤2：等待 Pod 状态 Ready**

等待大约 1 分钟左右，Pod 状态变为 `Ready` 。执行命令 `kubectl get pod occlum-app-builder` ，输出结果如下：

```
$ kubectl get pod occlum-app-builder
NAME                 READY   STATUS    RESTARTS   AGE
occlum-app-builder   1/1     Running   0          15s
```

- **步骤3：登录到** **occlum-app-builder  容器**

```
kubectl exec -it occlum-app-builder -c occlum-app-builder -- /bin/bash
```

- **步骤4：在容器内安装 docker**

参考 [docker 官方文档](https://docs.docker.com/engine/install/centos/) 安装 docker。注意容器内是没有安装 systemd 的，也就不能用 systemd 来启动 docker。

- **步骤5：启动 docker**

```
nohup dockerd -b docker0 --storage-driver=vfs &
```

- **步骤6：确保 docker 服务已启动**

执行命令 `docker ps` ，输出结果如下所示：

```
$ docker ps 
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              
```

### 2. 在容器内开发“Hello World”应用

如果你想用 SGX SDK 写一个 SGX Hello World 应用的话，你需要写上百行的代码。除此之外，你还要花时间去学习 API、编程模型和 SGX SDK的构建系统。

而有了 Occlum 后，你不必去写任何与 SGX 相关的代码，只需要几个简单的命令就能用 SGX 透明地把应用保护起来。

- **步骤1：在容器内创建工作目录**

```
mkdir /root/occlum_workspace && cd /root/occlum_workspace/
```

- **步骤2：用 C 语言编写 Hello World 代码**

```
cat << EOF > /root/occlum_workspace/hello_world.c
#include <stdio.h>
#include <unistd.h>

int main() {
    while(1){
      printf("Hello World!\n");
      fflush(stdout);
      sleep(5);
    }
}
EOF
```

- **步骤3：用 Occlum 提供的工具编译代码**

Occlum 支持 musl libc，不支持 glic，可用 Occlum 内置的编译工具 occlum-gcc 来编译 C 程序。执行如下命令编译代码：

```
occlum-gcc -o hello_world hello_world.c
```

- **步骤4：执行命令 occlum init 初始化 Occlum 上下文**

```
mkdir occlum_context && cd occlum_context
occlum init
```

`occlum init` 命令会在当前目录中生成一个状态文件，该文件会记录编译或运行状态，从而形成一个 Occlum 实例。该目录下只能被一个应用实例使用；不同应用或同一应用的多个实例同样也需要使用不同的 Occlum 实例。

- **步骤5：用 occlum build 命令生成一个安全的 Occlum 文件系统和一个 Occlum SGX enclave**

```
cp ../hello_world image/bin/
occlum build
```

`image` 目录是通过 `occlum init` 命令初始化的。 `image` 目录结构是一个迷你文件系统，包含有 `/bin` , `lib` , `root` ， `tmp` 等目录。把程序 `hello_world`  拷贝到 `image/bin` 目录后， `image` 目录会被 `occlum build` 命令打包并生成一个安全的 Occlum 文件系统和一个 Occlum SGX enclave。

- **步骤6：用 occlum run 命令执行跑在 SGX enclave 里的用户程序**

```
occlum run /bin/hello_world
```

`occlum run`  命令会启动一个 Occlum SGX enclave，验证额并加载相关的 Occlum 文件系统，并生产出一个 LibOS 进程去执行 /bin/hello_world 程序。

### 3. 构建“Hello Wrold”镜像

- **步骤1：编写 Dockerfile**

```
cat << EOF >Dockerfile
FROM scratch
ADD image /
ENTRYPOINT ["/bin/hello_world"]
EOF
```

建议使用 scratch 做基础镜像。scratch 是一个特殊的镜像，不会占用任何空间，从而使得镜像足够小，镜像越小意味着越小的可信基础（TCB）和更小的攻击面。 `Add image` 把 Occlum 的 image 目录放到 docker 镜像的根目录， `ENTRYPOINT ["/bin/hello_world"]`  设置 `/bin/hello_world` 为容器的入口点。

- **步骤2：构建并推送“Hello World”镜像到镜像仓库**

比如你在命名空间 `inclavarecontainers` 下创建了 docker 镜像仓库 `occlum-hello-world`，你可以把镜像命名为 `docker.io/inclavarecontainers/occlum-hello-world:scratch` 并推送到镜像仓库。

```
docker build -f "Dockerfile" -t "docker.io/inclavarecontainers/occlum-hello-world:scratch" .
docker push "docker.io/inclavarecontainers/occlum-hello-world:scratch"
```

### 4. 运行“Hello World”容器

- **步骤1：创建“Hello World” Pod**

先退出 Occlum SDK 容器，在宿主机上执行下面的脚本：

```
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: helloworld
  name: helloworld
spec:
  runtimeClassName: rune
  containers:
  - command:
    - /bin/hello_world
    env:
    - name: RUNE_CARRIER
      value: occlum
    image: docker.io/inclavarecontainers/occlum-hello-world:scratch
    imagePullPolicy: IfNotPresent
    name: helloworld
    workingDir: /run/rune
EOF
```

**注意:** `runtimeClassName` 字段应该设置为 `rune` 。容器中设置环境变量 `RUNE_CARRIER` 是告诉 `rune` 去创建一个 SGX Occlum 容器。

另外，可以通过如下环境变量来控制 Occlum 参数：

| 变量名                            | 默认值     |
| --------------------------------- | ---------- |
| OCCLUM_USER_SPACE_SIZE            | 256MB      |
| OCCLUM_KERNEL_SPACE_HEAP_SIZE     | 32MB       |
| OCCLUM_KERNEL_SPACE_STACK_SIZE    | 1MB        |
| OCCLUM_MAX_NUM_OF_THREADS         | 32         |
| OCCLUM_PROCESS_DEFAULT_STACK_SIZE | 4MB        |
| OCCLUM_PROCESS_DEFAULT_HEAP_SIZE  | 32MB       |
| OCCLUM_PROCESS_DEFAULT_MMAP_SIZE  | 80MB       |
| OCCLUM_DEFAULT_ENV                | OCCLUM=yes |
| OCCLUM_UNTRUSTED_ENV              | EXAMPLE    |

- **步骤2：等待 Pod 状态变为 Ready**

```
kubectl get pod helloworld
```

- **步骤3：打印容器日志**

执行命令 `kubectl logs -f helloworld` , 终端会每隔 5 秒打印一条 "Hello world"，输出内容如下:

```
$ kubectl logs -f helloworld
Hello World!
Hello World!
Hello World!
```

### 5. 清理

执行如下命令删除 Pod `helloworld` and `occlum-app-builder` ：

```
kubectl delete pod helloworld
kubectl delete pod occlum-app-builder
```
