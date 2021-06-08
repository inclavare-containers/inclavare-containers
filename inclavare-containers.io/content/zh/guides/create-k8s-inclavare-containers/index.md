---
title: "创建一个机密计算Kubernetes集群"
description: "本指南将介绍基于inclavare-containers 创建一个机密计算Kubernetes集群"
github: "https://github.com/alibaba/inclavare-containers"
projects: [
  {name: "Inclavare Containers", link: "https://github.com/alibaba/inclavare-containers"},
]
---
这篇文档展示了如何基于 Inclavare-Containers 运行时创建一个单节点的 Kubernetes 集群，Enclave Runtime 用的是 Occlum。

想了解 Inclavare-Containers 的工作原理，请参考 [《Inclavare Containers：业界首个面向机密计算场景的开源容器运行时》](/guides/open-source-container-runtime/)。

## 准备工作

- 准备一台硬件支持 Intel SGX 的裸金属服务器
- 确保操作系统是下面列表的一种：
  - CentOS 8.1 64位
  - Ubuntu 18.04 server 64位
- 根据操作系统，从官方提供的版本页中合适的 Inclavare-Containers 的安装包

| 组件名     | CentOS                              | Ubuntu                         |
| :--------- | :---------------------------------- | :----------------------------- |
| occlum-pal | occlum-pal-{version}.el8.x86_64.rpm | occlum-pal_{version}_amd64.deb |
| shim-rune  | shim-rune-{version}.el8.x86_64.rpm  | shim-rune_{version}_amd64.deb  |
| rune       | rune-{version}.el8.x86_64.rpm       | rune_{version}_amd64.deb       |



## 目标

- 安装 Intel SGX 软件栈，包括 Intel SGX 驱动，SGX SDK 和 SGX PSW；
- 安装 Occlum 软件栈，包括内核模块 enable-rdfsbase 和实现了 Enclave Runtime PAL API 的动态库 occlum-pal；
- 创建单节点的 Kubernetes 集群，Pod 配置 RuntimeClass 可创建 runc 容器或 Enclave 容器。

## 安装步骤

### 1. 安装 Intel SGX 软件栈

参考官方文档 [Intel SGX Installation Guide](https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Installation_Guide_Linux_2.9.1_Open_Source.pdf) 安装 Intel SGX 驱动，Intel SDK 和 Intel PSW。建议安装的版本是 2.9.1。

**注意：**请安装 OOT SGX 驱动，不支持安装支持 ECDSA 认证的驱动。

### 2. 安装 Occlum 软件栈

目前 Occlum 是 Inclavare-Containers 唯一支持的一种 Enclave Runtime，Occlum 软件栈包括 `enable-rdfsdbase` 和 `occlum-pal`。
`enable-rdfsdbase` 是 Occlum 所需的内核模块，该模块会开启 RDFSBASE, WRFSBASE, RDGSBASE, WRGSBASE 指令。
`occlum-pal` 实现了 [Enclave Runtime APL API v2](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/spec_v2.md)，用于 rune 和 Occlum 之间的通信。

- **步骤1：安装内核模块 enable-redfsbase**

  参考官方文档 https://github.com/occlum/enable_rdfsbase 安装 `enable-rdfsdbase`。

- **步骤2：安装 libsgx-uae-service**
     - CentOS

  切换到步骤 1 中的 SGX RPM 本地库目录，执行如下命令安装 libsgx-uae-service：

  ```bash
  sudo rpm -ivh libsgx-uae-service-2.9.101.2-1.el8.x86_64.rpm
  ```

  - Ubuntu

  ```bash
  wget https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/debian_pkgs/libs/libsgx-uae-service/libsgx-uae-service_2.9.101.2-xenial1_amd64.deb -O libsgx-uae-service_2.9.101.2-xenial1_amd64.deb
  sudo dpkg -i libsgx-uae-service_2.9.101.2-xenial1_amd64.deb
  ```

- **步骤3：安装 occlum-pal**

  - CentOS

  ```bash
  version=0.15.1-1
  sudo rpm -ivh occlum-pal-${version}.el8.x86_64.rpm
  ```

  - Ubuntu

  ```bash
  version=0.15.1-1
  sudo dpkg -i occlum-pal_${version}_amd64.deb
  ```

### 3. 安装容器运行时 runc 和 rune

`runc` 和 `rune` 都是符合 OCI Runtime 规范的命令行工具，可用来创建和运行容器。 `rune` 是在 `runc` 代码的基础上开发的，所以 `rune` 也能够运行 runc 容器。他们的区别在于 `rune` 能够在容器里运行一个可信的执行环境 Enclave，用以保护敏感的数据和组织不可信实体对数据的访问。

- **步骤1：下载二进制包 runc 并安装到目录 /usr/bin/runc 下**

```bash
wget https://github.com/opencontainers/runc/releases/download/v1.0.0-rc90/runc.amd64 -O /usr/bin/runc
chmod +x /usr/bin/runc
```

- **步骤2：安装 rune**

  - CentOS

  ```bash
  version=0.4.0-1
  sudo yum install -y libseccomp
  sudo rpm -ivh rune-${version}.el7.x86_64.rpm
  ```

  - Ubuntu

  ```bash
  version=0.4.0-1
  sudo dpkg -i rune_${version}_amd64.deb
  ```

### 4. 安装 shim-rune

- CentOS

```bash
version=0.4.0-1
sudo rpm -ivh shim-rune-${version}.el8.x86_64.rpm
```

- Ubuntu

```bash
version=0.4.0-1
sudo dpkg -i shim-rune_${version}_amd64.deb
```

### 5. 安装和配置 containerd

containerd 一个工业级标准的容器运行时，它强调简单性、健壮性和可移植性。可以在宿主机中管理完整的容器生命周期：容器镜像的传输和存储、容器的执行和管理、存储和网络等；
可从 containerd [下载页面](https://containerd.io/downloads/) 选择合适的版本来安装。

- **步骤1：执行下面命令安装 containerd-1.3.4**

```bash
curl -LO https://github.com/containerd/containerd/releases/download/v1.3.4/containerd-1.3.4.linux-amd64.tar.gz
tar -xvf containerd-1.3.4.linux-amd64.tar.gz
cp bin/* /usr/local/bin
```

- **步骤2：配置 containerd.service**

```bash
cat << EOF >/etc/systemd/system/containerd.service
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target

[Service]
ExecStartPre=/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd
Restart=always
RestartSec=5
Delegate=yes
KillMode=process
OOMScoreAdjust=-999
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
EOF
```

- **步骤3：配置 containerd 配置文件 config.toml**

```bash
mkdir /etc/containerd
cat << EOF >/etc/containerd/config.toml
[plugins]
  [plugins.cri]
    sandbox_image = "registry.cn-hangzhou.aliyuncs.com/acs/pause-amd64:3.1"
    [plugins.cri.containerd]
      snapshotter = "overlayfs"
      [plugins.cri.containerd.default_runtime]
        runtime_type = "io.containerd.runtime.v1.linux"
        runtime_engine = "/usr/bin/runc"
        runtime_root = ""
      [plugins.cri.containerd.runtimes.rune]
        runtime_type = "io.containerd.rune.v2"
EOF
```

- **步骤4：启用并启动 containerd 服务**

```bash
sudo systemctl enable containerd.service
sudo systemctl restart containerd.service
```

- **步骤5：提前下载 Occlum SDK 镜像（可选）**

建议提前下载 Occlum SDK 镜像，shim-rune 会用该镜像启动容器并在容器内实现镜像转换。首次下载会比较耗时，提前下载好可以缩短 Enclave 容器的创建时间。
执行下面命令下载 Occlum SDK 镜像：

```bash
ctr image pull docker.io/occlum/occlum:0.15.1-ubuntu18.04
```

### 6. 创建单节点 Kubernetes 集群

- **步骤1：设置 Kubernetes 所需的内核参数**

加载内核模块 `br_netfilter` ，设置内核参数 `net.bridge.bridge-nf-call-iptables` 和 `net.ipv4.ip_forward` 为 1 。

```bash
sudo modprobe br_netfilter
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF
sudo sysctl --system
```


- **步骤2：配置安装包仓库，用来下载 kubelet，kubeadm 和 kubectl**

  - CentOS

  ```bash
  cat << EOF >/etc/yum.repos.d/kubernetes.repo
  [kubernetes]
  name=Kubernetes
  baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
  enabled=1
  gpgcheck=1
  repo_gpgcheck=1
  gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
  EOF
  ```


  - Ubuntu

  ```bash
  sudo apt update && sudo apt install -y apt-transport-https curl
  curl -s https://mirrors.aliyun.com/kubernetes/apt/doc/apt-key.gpg | sudo apt-key add -
  echo "deb https://mirrors.aliyun.com/kubernetes/apt/ kubernetes-xenial main" >>/etc/apt/sources.list.d/kubernetes.list
  ```


- **步骤3：安装 kubelet，kubeadm 和 kubectl**

  这里我们安装 v1.16.9 的 kubelet，kubeadm 和 kubectl。你也可以选择其他版本，但建议安装大于等于 v1.16 的版本。

  - CentOS

  ```bash
  sudo setenforce 0
  sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
  kubernetes_version=1.16.9
  sudo yum install -y --setopt=obsoletes=0 kubelet-${kubernetes_version} \
   kubeadm-${kubernetes_version} kubectl-${kubernetes_version} \
   --disableexcludes=kubernetes
  ```


  - Ubuntu

  ```bash
  sudo setenforce 0
  sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
  kubernetes_version=1.16.9
  sudo apt update && apt install -y kubelet=${kubernetes_version}-00 \
   kubeadm=${kubernetes_version}-00 kubectl=${kubernetes_version}-00 
  ```


- **步骤4：配置 kubelet 配置文件**

  - CentOS

  ```bash
  cat << EOF >/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf
  # Note: This dropin only works with kubeadm and kubelet v1.11+
  [Service]
  Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
  Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
  Environment="KUBELET_SYSTEM_PODS_ARGS=--max-pods 64 --pod-manifest-path=/etc/kubernetes/manifests"
  Environment="KUBELET_NETWORK_ARGS=--network-plugin=cni --cni-conf-dir=/etc/cni/net.d --cni-bin-dir=/opt/cni/bin"
  Environment="KUBELET_DNS_ARGS=--pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/acs/pause-amd64:3.0 --cluster-domain=cluster.local --cloud-provider=external"
  Environment="KUBELET_EXTRA_ARGS=--container-runtime=remote --container-runtime-endpoint=/run/containerd/containerd.sock"
  ExecStart=
  ExecStart=/usr/bin/kubelet \$KUBELET_KUBECONFIG_ARGS \$KUBELET_CONFIG_ARGS \$KUBELET_SYSTEM_PODS_ARGS \$KUBELET_NETWORK_ARGS \$KUBELET_DNS_ARGS \$KUBELET_EXTRA_ARGS
  EOF
  ```

  - Ubuntu

  ```bash
  cat << EOF >/etc/resolv.conf.kubernetes
  nameserver 8.8.8.8
  options timeout:2 attempts:3 rotate single-request-reopen
  EOF
  
  cat << EOF >/etc/systemd/system/kubelet.service.d/10-kubeadm.conf
  # Note: This dropin only works with kubeadm and kubelet v1.11+
  [Service]
  Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
  Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
  Environment="KUBELET_SYSTEM_PODS_ARGS=--max-pods 64 --pod-manifest-path=/etc/kubernetes/manifests"
  Environment="KUBELET_NETWORK_ARGS=--network-plugin=cni --cni-conf-dir=/etc/cni/net.d --cni-bin-dir=/opt/cni/bin"
  Environment="KUBELET_DNS_ARGS=--pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/acs/pause-amd64:3.0 --cluster-domain=cluster.local --cloud-provider=external --resolv-conf=/etc/resolv.conf.kubernetes"
  Environment="KUBELET_EXTRA_ARGS=--container-runtime=remote --container-runtime-endpoint=/run/containerd/containerd.sock"
  ExecStart=
  ExecStart=/usr/bin/kubelet \$KUBELET_KUBECONFIG_ARGS \$KUBELET_CONFIG_ARGS \$KUBELET_SYSTEM_PODS_ARGS \$KUBELET_NETWORK_ARGS \$KUBELET_DNS_ARGS \$KUBELET_EXTRA_ARGS
  EOF
  ```

- **步骤5：启用 kubelet 服务**

```bash
sudo systemctl enable kubelet.service
```


- **步骤6：用 kubeadm 初始化集群**

kubeadm 可通过参数 `--kubernetes-version` 设置集群的版本，Kubernetes 的集群版本一定要与 kubectl 的版本一致。可通过参数 `--pod-network-cidr` 和 `--``service-cidr` 分别设置 Kubernetes 的 Pod 和 Service 的 CIDR, 并确保这些 CIDR 不与 Host IP 有冲突。比如 Host IP 是 192.168.1.100, 可执行如下命令初始化集群：

```bash
kubeadm init --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers \
 --kubernetes-version=v1.16.9 \
 --pod-network-cidr="172.21.0.0/20" --service-cidr="172.20.0.0/20"
```


- **步骤7：配置 kubeconfig**

为了能使 kubectl 工作，可执行如下命令配置 kubeconfig。以下命令也是 `kubeadmin init` 输出结果的一部分：

```bash
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```


- **步骤8：安装网络插件**

在没装网络插件前，集群 Node 状态会是 `NotReady`。执行如下命令安装网络插件 flannel，并确保 Node 状态变为 `Ready` ：

```bash
kubectl taint nodes $(hostname | tr 'A-Z' 'a-z') node.cloudprovider.kubernetes.io/uninitialized-
kubectl taint nodes $(hostname | tr 'A-Z' 'a-z') node-role.kubernetes.io/master-
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/2140ac876ef134e0ed5af15c65e414cf26827915/Documentation/kube-flannel.yml
```


- **步骤9：检查 Pod 状态**

执行命令 `kubectl get pod -A` 确保所有 Pod 状态变为 `Ready` ，输出结果如下所示：

```undefined
$ kubectl get pod -A
NAMESPACE     NAME                                              READY   STATUS    RESTARTS   AGE
kube-system   coredns-67c766df46-bzmwx                          1/1     Running   0          74s
kube-system   coredns-67c766df46-l6blz                          1/1     Running   0          74s
kube-system   etcd-izuf68q2tx28s7tel52vb0z                      1/1     Running   0          20s
kube-system   kube-apiserver-izuf68q2tx28s7tel52vb0z            1/1     Running   0          12s
kube-system   kube-controller-manager-izuf68q2tx28s7tel52vb0z   1/1     Running   0          28s
kube-system   kube-flannel-ds-amd64-s542d                       1/1     Running   0          56s
kube-system   kube-proxy-fpwnh                                  1/1     Running   0          74s
kube-system   kube-scheduler-izuf68q2tx28s7tel52vb0z            1/1     Running   0          20s
```


### 7. 配置 RuntimeClass

- **步骤1：创建 runc 和 rune RuntimeClass 对象**

```bash
cat << EOF | kubectl apply -f -
apiVersion: node.k8s.io/v1beta1
handler: runc
kind: RuntimeClass
metadata:
  name: runc
EOF
```


```bash
cat << EOF | kubectl apply -f -
apiVersion: node.k8s.io/v1beta1
handler: rune
kind: RuntimeClass
metadata:
  name: rune
EOF
```


- **步骤2：确保 RuntimeClass 对象创建成功**

执行命令 `kubectl get runtimeclass` 可以列出 `runc` 和 `rune` RuntimeClass 对象，输出结果如下：

```undefined
$ kubectl get runtimeclass
NAME   CREATED AT
runc   2020-05-06T06:57:51Z
rune   2020-05-06T06:57:48Z
```
