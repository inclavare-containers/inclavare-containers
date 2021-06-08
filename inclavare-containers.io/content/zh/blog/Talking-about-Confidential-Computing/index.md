---
title: "浅谈机密计算-发表在Inclavare Containers开源之际"
author: "乾越"
description: "浅谈机密计算-发表在Inclavare Containers开源之际"
categories: "Inclavare-containers"
tags: ["机密计算","Inclavare Containers"]
date: 2020-08-11T15:00:00+08:00
cover: "/confidential.png"
---

> Inclavare Containers
> Inclavare Containers是面向云原生场景的机密计算容器技术栈。它结合了机密计算的特点，为开源社区提供面向云原生场景的机密计算容器技术和安全架构。通过与容器技术结合的方式，Inclavare Containers能够大幅降低机密计算的开发和使用成本。同时，Inclavare Containers基于处理器硬件辅助Enclave技术，提供对多种Enclave形态的支持。

## 什么是 Inclavare Containers?

Inclavare，是 Enclave 一词的拉丁语词源，读音是 [ˈinklɑveə]。

Enclave 指的是一种受保护的执行环境，能为其中的敏感和机密数据提供基于密钥学算法的强安全隔离，阻止不可信的实体访问用户的数字资产。

InclavarContainers 是由阿里云操作系统安全团队和阿里云云原生容器服务团队主导，并联合了阿里经济体内多个研发团队（蚂蚁安全计算团队、云安全团队、语言 runtime 团队等）共同研发的面向机密计算场景的开源容器运行时技术栈。

![image](https://intranetproxy.alipay.com/skylark/lark/0/2020/jpeg/301940/1597993311491-74dc939a-ec4b-4d16-8b4f-32340698b8a2.jpeg)

其中：

- Occlum：由蚂蚁安全计算团队自研的实现了内存安全的多进程 library OS（rune 的默认 enclave runtime）
- Dragonwell：由阿里编译器团队定制的 LTS OpenJDK 发行版本（后续会提供 Golang 的支持）
- Graphene：基于 Intel SGX（Software Guard Extensions）技术并可以运行未经修改程序的开源 library OS（阿里云安全团队合作贡献 Golang 支持）
- enclave-device-plugin：由阿里云容器服务团队和蚂蚁金服安全计算团队针对 Enclave 硬件技术联合开发的 Kubernetes Device Plugin

Inclavare Containers 的定位是提供面向机密计算的容器化技术底座，主打开源、社区、标准和生态，目前已经在 github 上开源： https://github.com/alibaba/inclavare-containers ；Inclavare Containers 目前支持 Intel SGX 机密计算技术。



## 市场需求

越来越多的租户业务尤其是企业负载需要利用云计算提供的弹性资源进行海量数据处理。这类租户要求 CSP（Cloud Service Provider）能够提供更好的安全和隔离解决方案，尤其是在计算阶段处理租户机密数据的过程中，机密数据不能以明文形式暴露在内存中，同时租户运行环境的安全性又不能依赖于 CSP。目前这个数据隐私问题是困扰企业用户上云的隐忧之一，需要机密计算这种工程技术来解决。



## 机密计算的核心功能

机密计算中的三个最核心的关键功能分别是：

- 基于密码学的内存隔离
- 支持远程证明
- CSP 不在租户的 TCB（Trusted Computing Base）中

Intel SGX技术实现了上述关键功能。Intel SGX 提供的隐私数据防护能力要高于纯粹的内存加密技术，原因是它提供了最小的、应用级粒度的 TCB 以及基于密码学的强安全隔离；但在提供强安全特性的同时，也伴随着很多兼容性和性能问题。Inclavare Containers 正是看到了这样的问题，所以整合了容器生态、library OS 和语言 Runtime 这三大技术体系和资源，目的是大幅度降低用户的使用门槛，并将 Intel SGX Enclave 这个形态牵引至云原生的场景里。



## 阿里云 ACK-TEE

ACK-TEE 是阿里云容器团队、操作系统安全团队、蚂蚁安全团队、阿里云安全团队和编译器团队共同打造的可信计算容器平台，旨在为对数字资产（算法、数据、代码）有强安全诉求的云用户提供基于 Intel SGX 硬件加密技术的可信计算环境（TEE），降低机密计算技术的应用门槛，简化可信 / 机密应用的开发、交付和管理成本。同时，ACK-TEE 致力于打造可信业务 / 应用 / 二方产品上云的云原生机密计算通用底座。

ACK 加密计算托管集群（ACK-TEE 1.0）已于 2020 年 1 月上线，支持基于 SGX SDK 开发的可信应用以及 Occlum、Graphene-SGX 应用等，支持 EPC 内存调度。



## 结语

数据安全防护的重要性在快速提升，这给整个数据安全市场的发展带来了巨大的潜力和机会。尤其是机密计算领域，Gartner 在 2019 年发布的计算基础设施技术成熟度曲线中，首次将机密计算列入 Innovation Trigger 阶段，这也表示了机密计算在全球也属于新兴领域。

机密计算本身是关注租户利益的，CSP 也意识到了这个问题并在进行技术和产品研发，但这不绝不是一蹴而就的，而是一个循序渐进的过程，因此就开始出现了非面向机密计算的 Enclave 形式。对此，CSP 应当在横向上支持不同的硬件安全能力和 Enclave 形态，成就立体的技术解决方案，包括面向机密计算和非机密计算，并提供更多的可选项，以涵盖最广泛的有对计算时数据安全防护需求的用户群体。Inclavare Containers 也将这一目标作为其使命。

最后，再次审视机密计算场景下的租户立场： **希望借助 CSP 提供的云计算能力的同时，又不信任 CSP。** 一个看似矛盾但实为拥有巨大共赢潜力的需求，正是驱动 CSP 真正地完全站在客户的角度去思考问题的绝好机遇。

以数据安全为根，以 Inclavare Containers 为枝，我们冀望着机密计算这棵幼苗能够茁壮成长为一颗苍天大树。
