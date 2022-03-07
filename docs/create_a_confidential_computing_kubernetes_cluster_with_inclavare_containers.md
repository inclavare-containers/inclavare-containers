# Create a confidential computing Kubernetes cluster with inclavare-containers based on Occlum

This page shows how to create a single control-plane Kubernetes and install the software required to run confidential computing containers with Occlum in the Kubernetes cluster.
## Before you begin

- A machine with Intel SGX hardware support.
- Make sure you have one of the following operating systems:
   - Ubuntu 18.04 server 64bits
   
## Objectives

- Install the Intel SGX software stack.
- Install the Occlum software stack.
- Create a single control-plane Kubernetes cluster for running confidential computing containers with Occlum.

## Instructions

### 1. Add inclavare-containers repository

- On Ubuntu

```bash
# install gnupg and wget
sudo apt-get install -y gnupg wget

# add the repository to your sources
echo 'deb [arch=amd64] https://mirrors.openanolis.cn/inclavare-containers/deb-repo bionic main' | tee /etc/apt/sources.list.d/inclavare-containers.list

# add the key to the list of trusted keys used by the apt to authenticate packages
wget -qO - https://mirrors.openanolis.cn/inclavare-containers/deb-repo/DEB-GPG-KEY.key  | sudo apt-key add -

# set a higher priority to epm to avoid conflicts with another epm package which reside in `mirrors.cloud.aliyuncs.com`
cat << EOF >/etc/apt/preferences.d/inclavare-containers
Package: epm
Pin: origin mirrors.openanolis.cn
Pin-Priority: 1000
EOF

# update the apt
sudo apt-get update
```

### 2. Install Linux SGX software stack
The Linux SGX software stack is comprised of Intel SGX driver, Intel SGX SDK, and Intel SGX PSW. 
Please follow [Intel SGX Installation Guide Linux 2.14](https://download.01.org/intel-sgx/sgx-linux/2.14/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) to install SGX driver, SDK and PSW, the recommended version is 2.14.
                                                                             
### 3. Install Occlum software stack
[Occlum](https://github.com/occlum/occlum) is the only enclave runtime supported by shim-rune currently. 
`enable-rdfsdbase` is a Linux kernel module which enables Occlum to use rdfsbase-family instructions in enclaves.

- Step 1. Install kernel module enable-rdfsdbase

    Please follow the [documentation](https://github.com/occlum/enable_rdfsbase) to install `enable-rdfsdbase`.

- Step 2. Install package libsgx-uae-service
    
    `libsgx-uae-service` package is required by occlum, install libsgx-uae-service use the following command:
    - On Ubuntu
    ```
    sudo apt-get install libsgx-uae-service
    ```
    
- Step 3. Install occlum
   - On Ubuntu
    ```bash
    sudo apt-get install occlum
    ```

### 4. Install rune
`rune` is a CLI tools for spawning and running containers according to the OCI specification. The codebase of the `rune` is a fork of [runc](https://github.com/opencontainers/runc), so `rune` can be used as `runc` if enclave is not configured or available. The difference between them is `rune` can run a so-called enclave which is referred to as protected execution environment, preventing the untrusted entity from accessing the sensitive and confidential assets in use in containers.<br />
<br />
Install rune use the following commands:

- On Ubuntu
```bash
sudo apt-get install rune
```

### 5. Install epm
`epm` epm is a service that is used to manage the cache pools to optimize the startup time of enclave.<br />
<br />
Install epm use the following commands:

- On Ubuntu
```bash
sudo apt-get install epm
```


### 6. Install shim-rune
`shim-rune` resides in between `containerd` and `rune`, conducting enclave signing and management beyond the normal `shim` basis. `shim-rune` and `rune` can compose a basic enclave containerization stack for the cloud-native ecosystem.

- On Ubuntu
    ```bash
    sudo apt-get install shim-rune
    ```

### 7. Install and configure containerd
containerd is an industry-standard container runtime with an emphasis on simplicity, robustness and portability. It is available as a daemon for Linux and Windows, which can manage the complete container lifecycle of its host system: image transfer and storage, container execution and supervision, low-level storage and network attachments, etc.<br />You can download one of the containerd binaries on the [Download](https://containerd.io/downloads/) page.

- Step 1. Download and install containerd-1.3.4 as follows:
    ```bash
    curl -LO https://github.com/containerd/containerd/releases/download/v1.3.4/containerd-1.3.4.linux-amd64.tar.gz
    tar -xvf containerd-1.3.4.linux-amd64.tar.gz
    cp bin/* /usr/local/bin
    ```

- Step 2. Configure the containerd.service

    You can use systemd to manage the containerd daemon, and place the `containerd.service` to  `/etc/systemd/system/containerd.service`.
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

- Step 3. Configure the containerd configuration

    The daemon also uses a configuration file located in `/etc/containerd/config.toml` for specifying daemon level options.
    ```bash
    mkdir /etc/containerd
    cat << EOF >/etc/containerd/config.toml
    [plugins]
      [plugins.cri]
        sandbox_image = "registry.cn-hangzhou.aliyuncs.com/acs/pause-amd64:3.1"
        [plugins.cri.containerd]
          default_runtime_name = "rune"
          snapshotter = "overlayfs"
          [plugins.cri.containerd.runtimes.rune]
            runtime_type = "io.containerd.rune.v2"
    EOF
    ```

- Step 4. Enable and restart the containerd.service
    ```bash
    sudo systemctl enable containerd.service
    sudo systemctl restart containerd.service
    ```

### 8. Create a single control-plane Kubernetes cluster with kubeadm

- Step 1. Set the kernel parameters

    Make sure that the `br_netfilter` module is loaded and both `net.bridge.bridge-nf-call-iptables` and `net.ipv4.ip_forward` are set to 1 in your sysctl config.
    ```bash
    sudo modprobe br_netfilter
    cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
    net.bridge.bridge-nf-call-ip6tables = 1
    net.bridge.bridge-nf-call-iptables = 1
    net.ipv4.ip_forward = 1
    EOF
    sudo sysctl --system
    ```

- Step 2. Configure the kubernets package repository for downloading kubelet, kubeadm and kubelet

   - On Ubuntu
    ```bash
    sudo apt update && sudo apt install -y apt-transport-https curl
    curl -s https://mirrors.aliyun.com/kubernetes/apt/doc/apt-key.gpg | sudo apt-key add -
    echo "deb https://mirrors.aliyun.com/kubernetes/apt/ kubernetes-xenial main" >>/etc/apt/sources.list.d/kubernetes.list
    ```


- Step 3. Install kubelet, kubeadm and kubectl

    Set SELinux in permissive mode and install kubelet, kubeadm and kubectl of version v1.16.9, you can choose other versions you like, but it is recommend that you use the versions greater than or equal to v1.16.

   - On Ubuntu
    ```bash
    sudo setenforce 0
    sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
    kubernetes_version=1.16.9
    sudo apt update && apt install -y kubelet=${kubernetes_version}-00 \
     kubeadm=${kubernetes_version}-00 kubectl=${kubernetes_version}-00 
    ```

- Step 4. Configure the kubelet configuration file

    Configure the kubelet configuration file `10-kubeadm.conf`, specify the runtime to containerd by arguments `--container-runtime=remote` and `--container-runtime-endpoint`.

   - On Ubuntu
    ```bash
    # Note: To avoid forwarding loop, create a new nameserver instead of the default loopback address 127.0.0.53 
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

- Step 5. Enable the kubelet.service
    ```bash
    sudo systemctl enable kubelet.service
    ```

- Step 6. Initialize the Kubernetes cluster with kubeadm

    The version of Kubernetes must match with the kubelet version. You can specify the Kubernetes Pod and Service CIDR block with arguments `pod-network-cidr`  and `service-cidr`,  and make sure the CIDRs are not conflict with the host IP address.  For example, if the host IP address is `192.168.1.100`,  you can initialize the cluster as follows:
    ```bash
    kubeadm init --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers \
     --kubernetes-version=v1.16.9 \
     --pod-network-cidr="172.21.0.0/20" --service-cidr="172.20.0.0/20"
    ```

- Step 7. Configure kubeconfig

    To make kubectl work, run these commands, which are also part of the `kubeadm init` output:
    ```bash
    mkdir -p $HOME/.kube
    sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    sudo chown $(id -u):$(id -g) $HOME/.kube/config
    ```

- Step 8. Install the network addon

    Install the network addon `flannel`  and wait for the node status to `Ready`.
    ```bash
    kubectl taint nodes $(hostname | tr 'A-Z' 'a-z') node.cloudprovider.kubernetes.io/uninitialized-
    kubectl taint nodes $(hostname | tr 'A-Z' 'a-z') node-role.kubernetes.io/master-
    kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/2140ac876ef134e0ed5af15c65e414cf26827915/Documentation/kube-flannel.yml
    ```

- Step 9. Check the pod status

    Check the pod status with command `kubectl get pod -A`  and wait until all pods status are `Ready` , the output should like this:
    ```
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

### 9. Configure RuntimeClass

- Step 1. Apply the following yaml files to create `rune` RuntimeClass object

    ```yaml
    cat << EOF | kubectl apply -f -
    apiVersion: node.k8s.io/v1beta1
    handler: rune
    kind: RuntimeClass
    metadata:
      name: rune
    EOF
    ```

- Step 2. Make sure the `rune` RuntimeClass object is created

    List the runtimeClasses with command `kubectl get runtimeclass` and the output should like this:
    ```
    $ kubectl get runtimeclass
    NAME   CREATED AT
    rune   2020-05-06T06:57:48Z
    ```

## What's Next

- [Develop and deploy a "Hello World" container in Kubernetes cluster](develop_and_deploy_hello_world_application_in_kubernetes_cluster.md)
