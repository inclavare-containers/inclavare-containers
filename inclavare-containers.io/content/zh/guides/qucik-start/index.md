---
title: "快速开始"
description: "本指南将基于Inclavare Containers快速构建运行安全应用"
github: "https://github.com/alibaba/inclavare-containers"
projects: [
  {name: "Inclavare Containers", link: "https://github.com/alibaba/inclavare-containers"}, 
]
---


## 准备工作

### 安装Intel SGX

请参考[Intel 安装文档](https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Installation_Guide_Linux_2.9.1_Open_Source.pdf)来安装Intel SGX驱动，Intel PSW和Intel SDK。 

### 安装enable-rdfsdbase
    
参考[安装文档](https://github.com/occlum/enable_rdfsbase)进行安装内核模块 `enable-rdfsdbase`.

## 构建occlum 应用容器镜像

请参考[文档](https://github.com/alibaba/inclavare-containers/blob/master/docs/running_rune_with_occlum.md#build-occlum-application-container-image)构建occlum 应用容器镜像。

## 安装Occlum

### 安装libsga-uae-service
   occlum-pal 依赖了 sgx-uae 服务，所以需要提前安装。请参考[Intel 安装文档](https://download.01.org/intel-sgx/sgx-linux/2.9.1/docs/Intel_SGX_Installation_Guide_Linux_2.9.1_Open_Source.pdf) 进行安装。
    
### 安装occlum-pal
   从[链接](https://github.com/alibaba/inclavare-containers/releases)下载occlum-pal的安装包，按照一下步骤安装：

- On CentOS

```bash
version=0.15.1-1
sudo rpm -ivh occlum-pal-${version}.el8.x86_64.rpm
```

- On Ubuntu

```bash
version=0.15.1-1
sudo dpkg -i occlum-pal_${version}_amd64.deb
```

## 安装rune
   从[链接](https://github.com/alibaba/inclavare-containers/releases)下载rune的安装包，按照一下步骤安装：

- On CentOS

```bash
version=0.4.0-1
sudo yum install -y libseccomp
sudo rpm -ivh rune-${version}.el8.x86_64.rpm
```

- On Ubuntu

```bash
version=0.4.0-1
sudo dpkg -i rune_${version}_amd64.deb
```

## 配置OCI运行时
在dockerd 配置文件中（例如：/etc/docker/daemon.json）添加`rune`OCI运行时：
```shell
{
    "runtimes": {
        "rune": {
            "path": "/usr/bin/rune",
            "runtimeArgs": []
        }
    }
}
```
然后重启dockerd。

您可以使用以下命令检查`rune`是否已正确添加到OCI运行时中
```shell
docker info | grep rune
Runtimes: rune runc
```

## 使用rune运行occlum应用镜像
```shell
docker run -it --rm --runtime=rune \
  -e ENCLAVE_TYPE=intelSgx \
  -e ENCLAVE_RUNTIME_PATH=/opt/occlum/build/lib/libocclum-pal.so.0.15.1 \
  -e ENCLAVE_RUNTIME_ARGS=./ \
  ${Occlum_application_image}
```

