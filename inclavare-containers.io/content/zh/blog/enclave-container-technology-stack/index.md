---
title: "面向机密计算的Enclave容器技术栈"
author: "乾越"
description: "本期内容来自阿里巴巴操作系统安全创新团队的负责人、Inclavare Containers项目的创始人乾越，分享主题——《Inclavare Containers - 面向机密计算的Enclave容器技术栈》。"
categories: "Inclavare Containers"
tags: ["机密计算","Inclavare Containers"]
date: 2020-09-03T20:00:00+08:00
cover: "/jiagou.png"
---

编者注：本期内容来自阿里巴巴操作系统安全创新团队的负责人、Inclavare Containers项目的创始人乾越，分享主题——《Inclavare Containers - 面向机密计算的Enclave容器技术栈》。

内容提要：<br />
✔云原生场景下的数据安全威胁和风险<br />
✔机密计算是如何为数据在计算阶段提供安全防护的<br />
✔Inclavare Containers如何提升容器的数据安全性的

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/312725/1599119350744-d2c57da2-5238-4183-87b6-9156074fc067.png#alt=%E4%B9%BE%E8%B6%8A.png)

以下是分享全文：

这是内容大纲，介绍了数据安全和机密计算的背景知识，也对Inclavare Containers开源项目、架构设计和部署方式分别进行了介绍。希望各位能够对Inclavare Containers技术栈有一个初步的认识。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713011919-af675434-acd9-406e-a87b-6952853e53f0.png#alt=undefined)

## 数据安全和机密计算
首先，让我们先了解一下当前云计算的数据安全威胁和风险。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713040672-e44544e0-07e3-4ec6-a0a8-9bf646564c44.png#alt=undefined)

目前攻击者泄露机密数据的最经典做法就是利用安全漏洞突破Hypervisor并渗透到其他租户Guest中。

第二种威胁则是CSP的管理员主动作恶窃取租户的机密数据。事实上，不管是哪一种威胁，对关注数据安全的用户来说，目前的传统云安全威胁模型存在一些固有的安全缺陷：攻击面大，且位于租户TCB中的这些特权组件又不受租户控制；即使没有发生入侵事件，租户的数据对CSP来说也是一览无余。

更进一步去思考可以发现，数据的状态有三种：存储、传输、计算。传统安全防护技术更关注前两者，忽视了数据在计算状态下的安全防护手段。

综上所述，可以得出一个结论：传统的安全威胁模型无法满足用户对机密数据安全防护的需求，这已成为部分企业上云的最大阻碍之一。企业客户不敢上云，他们手里的数据就形成了数据孤岛，最终阻止了有价值数据的流动性，因此数据作为资本和资产的社会价值以及经济价值都无法充分发挥。如果强行用基于现有的云安全威胁模型技术来支撑对机密数据安全防护有诉求的业务场景，就存在潜在的数据泄露风险；一旦真的因此发生了数据泄露事件，对CSP的声誉和经济利益造成极大损害。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713484527-b87e8c1c-012a-48df-adf8-d866c463baf3.png#alt=undefined)

下面我们进一步剖析租户与CSP双方在安全上的真实想法。

首先，所有的CSP都会宣称他们会为租户提供安全隔离的运行环境。本质上，CSP要求租户必须相信自己提供的安全服务，而其具体做法是：通过虚拟化层以及纵深防御机制防止恶意租户攻击自己的云基础设施，也就是说利用虚拟化多租隔离的副作用，满足一般用户的安全需求，同时假设用户是不可信的。

而从用户的视角来看，租户真正想要的其实是可信执行环境。从前面介绍的数据安全威胁和风险中可以看出：对持有机密数据的用户来说，CSP是完全不可信的。根因在于CSP可能作恶，或者攻击者可能攻破CSP并渗透到用户执行环境中。也就说“租户环境的安全性依赖于CSP控制的特权组件的安全性”这一事实，对有数据安全诉求的用户来说，是完全不可接受的。

综合来看，对租户来说，云环境是不可信的；租户真正需要的是覆盖数据全生命周期的综合性数据安全防护。对CSP来说，租户是不可信的；所以CSP需要安全隔离来防止来自恶意租户的安全威胁。

所以我们最终导出了这么一个结论：租户和CSP之间其实互不信任。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713080904-d97f70d5-c8fb-408b-ab9e-e284c6be2b00.png#alt=undefined)

我们的答案就是机密计算。首先什么是机密计算？

机密计算是一种通过软硬结合的方式，为用户提供一个完全隔离的可信执行环境的技术。机密计算能够对计算中的数据提供安全防护，防止CSP和任何第三方对执行环境中的数据进行窃取和篡改。

同时，机密计算具备三个显著性的特点：能够为租户的工作负载提供了基于内存加密技术的强安全隔离的TEE，因此CSP控制的组件无法直接访问TEE内的租户代码和数据；而远程证明保证了TEE的真实性，确保租户的工作负载确实运行在了真实可靠的TEE中。

综合上面几个特点可以得出一个结论：机密计算提供了一种面向防御面的、新形态的云安全威胁模型，即租户执行环境的安全性不再依赖CSP，用户上云但可以不再必须信任CSP。这些特点都是传统云安全威胁模型所不具备的，并直达云安全领域中数据安全这一核心问题。

最后，相比起同态加密、安全多方计算或零知识证明这些因受到性能制约而无法大规模使用的技术，机密计算能够充分利用处理器的通用运算能力，其实用性更高。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713102103-67548c18-9bfb-4482-96fe-7364cc93c22d.png#alt=undefined)

下面是目前机密计算产业的现状。

记得在Gartner 2019年计算基础设施技术成熟度曲线中。但在那之前，业界内的诸多厂商就已经开始关注并投入到机密计算中。

我们可以看到各大芯片厂家和CSP都在机密计算领域投入研发资源，并组建了“机密计算联盟”。该联盟专门针对云服务及硬件生态，致力于保护计算时的数据安全。

可以看到目前机密计算正处于百花齐发和百家争鸣的阶段，市场和商业化潜力非常巨大。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713572230-53a3441c-4d3e-47ac-81d3-c5f77d168f37.png#alt=undefined)

接下来介绍一下机密计算目前的不足。

- 
首先，工业界为机密计算提供的支撑技术总体而言还比较偏底层，比如Intel、微软和baidu都分别推出了SDK形式并基于Intel SGX硬件辅助enclave技术的开源软件，但这种软件技术有一定的开发门槛，除了要求开发者熟悉这些SDK本身的用法外，还需要开发者有额外的SGX相关的安全知识背景。此外，对中等以及以上规模软件的重构和适配的工作量很大，也容易出问题。

- 
此外，CSP提供的基于Intel SGX的Enclave技术解决方案也比较简单，目前大多数CSP还停留在提供IaaS层的裸金属服务器支持这个层面上，同时也没有好的容器形态部署方式；最重要的是没有体系化的云上机密计算基础设施服务的支撑。


![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713194473-c509a259-91eb-4d8d-8f46-fd9655499ca1.png#alt=undefined)

再简单介绍一下阿里云在机密计算领域的相关产品。

弹性裸金属服务器神龙是一种可弹性伸缩的高性能计算服务，计算性能与传统物理机无差别，具有安全物理隔离的特点。神龙的部分型号支持Intel SGX技术，用户可以自行在其上部署自己的机密计算应用。

阿里云区块链服务BaaS是企业级区块链平台服务，支持Hyperledger Fabric、蚂蚁金服自研区块链技术、以及企业以太坊Quorum（库room）。其后端提供了SGX安全保护等能力，打造多维度的区块链安全体系。

阿里云容器服务Kubernetes TEE版（ACK-TEE）是阿里云容器服务Kubernetes版ACK基于Intel SGX提供的可信应用或用于交付和管理机密计算应用的云原生一站式机密计算平台，旨在帮助用户保护数据使用中的安全性、完整性和机密性。阿里云被Gartner列为提供机密计算能力的典型厂商，并且今年Gartner也给阿里云在机密计算这个技术单项上因为ACK-TEE产品而给出了高评价。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713214980-ab563e1c-49c4-4f2e-ab34-00428150af20.png#alt=undefined)

再谈谈阿里云容器服务预计发布的ACK-TEE 2.0产品。

该产品的一个最显著特点是能够无缝运行用户制作的普通容器镜像，让普通用户保持与普通容器相同的使用体感，避免开发机密计算应用使用门槛高的问题，因此功能上支持原生应用，目标是普通用户。

此外，通过提供KMS-Enclave-Plugin controller，实现基于SGX的K8s集群级KMS服务，并与Enclave容器建立基于SGX硬件信任根的安全信道，实现remote secret provisioning。图中的Inclavare Containers是也是我们在后面的slide中将要重点介绍的核心技术栈。

在定位上，该产品希望能够集中阿里云容器技术在业内的技术优势，实现真正意义上的云原生机密计算集群，助力实现阿里云机密计算基础设施的愿景。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713236569-175e3198-42cb-4c61-bbe3-3061716a9c80.png#alt=undefined)

## Inclavare-Containers开源项目

这是关于Inclavare-Containers开源项目。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713262703-071deca0-2e11-436e-8beb-8db2be03514b.png#alt=undefined)

首先介绍一下Inclavare-Containers开源项目的背景。

正如前面介绍的，既然大多数CSP尝试在IaaS层，以资源供给的方式来推进机密计算的技术思路遇到了一些阻碍，那么我们则另辟蹊径：尝试将机密计算技术牵引到容器生态。我们的具体做法就是发起了Inclavare Containers项目。

该项目的目标比较简单，就是结合机密计算的特点，为业界提供面向机密计算领域的开源容器运行时引擎和完全面向机密计算的安全架构。

在价值方面，我们希望通过与容器技术结合，大幅降低机密计算的使用成本，让用户在保持与容器相近的使用体感的同时，还能享受到机密计算所能带来的高安全性；同时，Inclavare Containers将基于多种硬件辅助Enclave技术，提供对多种Enclave形态的支持，以覆盖对安全水位有不同要求的所有用户群体，为用户在安全和成本之间，提供更多的选择和灵活性。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713281392-2199116a-5c3e-493c-ae28-a0bd3a14f313.png#alt=undefined)

这里具体介绍一下Inclavare Contianers技术栈的几个特点：

首先，我们将Intel SGX技术与成熟的容器生态结合，将用户的敏感应用以Enclave容器的形式部署和运行；我们的目标是希望能够无缝运行用户制作的普通容器镜像，这将允许用户在制作镜像的过程中，无需了解机密技术所带来的复杂性，并保持与普通容器相同的使用体感。

其次，Intel SGX技术提供的保护粒度是应用而不是系统，在提供很高的安全防护手段的同时，也带来了一些编程约束，比如在SGX enclave中无法执行syscall指令；因此我们引入了LibOS技术，用于改善上述的软件兼容性问题，避免开发者在向Intel SGX Enclave移植软件的过程中，去做复杂的软件适配工作。

然后，虽然各个LibOS都在努力提升对系统调用的支持数量，但这终究难以企及原生Linux系统的兼容性，并且即使真的达成了这个目标，攻击面过大的缺点又会暴露出来。因此，Inclavare Containers通过支持Java等语言Runtime的方式，来补全和提升Enclave容器的泛用性，而不是将Enclave容器的泛用性绑定在“提升对系统调用的支持数量” 这一单一的兼容性维度上；此外，提供对语言Runtime的支持，也能将像Java这样繁荣的语言生态引入到机密计算的场景中，以丰富机密计算应用的种类和数量。

最后，通过定义通用的Enclave Runtime PAL API来接入更多类型的Enclave Runtime，比如LibOS就是一种Enclave Runtime形态；设计这层API的目标是为了繁荣Enclave Runtime生态，允许更多的Enclave Runtime通过对接Inclavare Containers上到云原生场景中，同时给用户提供更多的技术选择。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713304584-4a1d6b20-6279-466a-aad9-550a814d318b.png#alt=undefined)

下面介绍一下Inclavare Containers开源项目的情况。

首先，该开源项目具有业界创新性，它是首个面向云原生的机密计算场景下的开源容器运行时技术栈。不久前Inclavare Containers的核心组件rune被加入到了OCI Runtime参考实现列表中，这标志着rune做到了与OCI Runtime标准的兼容。目前，Intel已经确定参与到Inclavare Containers开源项目的共建中，并已经实质性地展开了开发工作。

目前该项目支持的几个关键功能有：支持通过K8s和Docker来启动Enclave容器，也就是说容器入口点指定的应用、或通过exec执行的应用，都将直接运行在容器内受保护的TEE环境中。目前在LibOS支持方面，Occlum提供了对rune和shim-rune的支持；同时，我们在内部也已经完成了Graphene对rune的支持。在语言Runtime方面，目前已经完成对Java、Golang和Python三种语言的支持，后续将持续完善并提高这些语言的基准测试用例的coverage。

在面向社区的monthly release方面，该项目会在每个月的月底进行一次小版本的发布，目前已经完成了0.1.0到0.4.0三个版本的发布。在每次release中，我们也会提供针对CentOS和Ubuntu两个主流Linux发型版本的安装包支持，社区用户通过安装包就能开始使用和部署Inclavare Containers。除了提供面向普通Linux发行版本的安装包支持外，针对阿里巴巴操作系统团队自研的Aliyun Linux 2发行版本，在提供安装包支持之上，还提供了专门的文档，指导用户通过在阿里云上购买实例的方式，来使用和部署Inclavare Containers，以便引导一些早期用户开始学习和体验该技术以及ACK-TEE产品。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713633085-d50e4c24-14eb-4efb-9709-6a0f1c742215.png#alt=undefined)

下面是Inclavare Containers开源项目的Milestone。

该项目从去年年底立项，再到3月完成PoC研发，并在5月中旬完成0.1.0的开源发布工作，经历了从无到有、从灵感创新到工程实践、从方向性探索到明确技术演进方向等一系列发展过程。

目前我们已经形成了系统性和阶段性的发展策略，并确定了未来目标规划以及未来演进的方向。在0.5.0版本中，Inclavare Containers将具备较为完整的K8s机密计算集群的能力，为接下来的ACK-TEE 2.0的产品化提供前提和基础；在明年，我们将持续迭代Inclavare Containers，并支撑ACK-TEE 2.0产品落地，同时也会完成一些新方向的技术探索和预研，为Inclavare Containers的下一代技术演进提前布局。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713648402-f573e7ae-b993-4f2c-b2e1-1f2866f3c646.png#alt=undefined)

目前，Inclavare Containers已经联合了阿里内部内部多个研发团队共建Inclavare Containers开源项目。

在对外合作方面，除了已经与Intel建立了合作关系外，计划在之后与其他芯片厂商陆续建立类似的合作关系；此外，我们已经开始与高校和学术界合作，以挖掘出Inclavare Containers在机密计算领域的更多潜能。

需要再强调的是，Inclavare Containers的定位是开源、社区、标准和生态，因此，我们希望能和业界的广大同僚一起共建和发展这项开源技术。

这里让我们再次审视机密计算场景下的用户诉求：用户希望借助CSP提供的云计算能力的同时，其数据的安全性又能依赖于CSP。这样一个看似矛盾，但实为有巨大共赢潜力的需求，正是驱动我们完全站在客户角度去思考问题的绝好机会。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713663080-eb8e8862-ea18-49b9-9df0-d1d0770aa121.png#alt=undefined)

## Inclavare Containers的架构设计

下面介绍一下Inclavare Containers的架构设计。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713679310-ac47adb3-501f-4015-bf53-e514e969fa21.png#alt=undefined)

下面是Inclavare Containers技术栈在K8s上的完整运行时组件图。

左边的kubelet和containerd都是标注组件；中间的shim-rune和rune是Inclavare Containers提供的组件；这里可以看到一个显著的特点，就是rune是可以作为runc使用的，因此rune能够启动和运行普通的pause容器和runc容器。

POD内的Enclave容器只能由rune创建。Enclave容器的1号进程被称为init-runelet，它通过PAL API来管理Enclave。在Enclave内，可以运行Occlum或Graphene这种LibOS，并在其上运行真正的Enclave应用或像Java等语言Runtime。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713694480-34eb7933-7b02-4782-a1cb-8b1b1fff6286.png#alt=undefined)

下面我们对Inclavare Containers的外部系统架构进行详细说明。

这里我们主要关注rune，它是实现enclave容器引擎的关键组件，并且遵守OCI Runtime规范。其核心组件libenclave提供了创建和管理Enclave容器的能力。Enclave容器内的管理进程，即init-runelet，是容器内的1号进程，init-runelet作为Enclave的载体，同时也负责启动和管理Enclave生命周期的责任。在创建Enclave的时候，init-runelet负责加载Enclave Image，并触发enclave内Enclave Runtime的初始化，然后将容器入口点程序加载至Enclave Runtime之上并运行。

可以看出，init-runelet承担着类似agent的角色，负责Enclave内外的沟通事务，比如enclave应用的stdio处理、信号转发等逻辑，都由init-runelet负责。

此外，Inclavare Containers提供的containerd-shim-rune除了实现Shim Runtime v2 API，也承担着Enclave管理的高级功能，比如Bundle转换，Enclave签名、远程证明等功能。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713706268-c4f41d0e-a529-4b2a-b6ea-17c63d01ea46.png#alt=undefined)

## Inclavare Containers的部署方式

下面介绍一下Inclavare Containers的部署方式。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713719819-3aac94b8-de08-4301-8c3a-4653fcc4f75b.png#alt=undefined)

下面介绍一下如何部署rune+OCI Bundle+Occlum的开发环境。

首先开发者下载并运行occlum sdk容器镜像，在其中通过Occlum SDK开发和构建Enclave应用，并用ESK对Enclave Image进行签名，然后通过docker将Enclave应用制作为Occlum应用容器镜像，接下来通过标准docker和containerd组件将Occlum应用容器镜像转换为OCI bundle，然后rune使用该Bundle，并最终启动Enclave容器运行Occlum和Enclave应用。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713734383-e549fed3-a9f8-405a-be21-c2ea4d33a4bd.png#alt=undefined)

下面介绍一下如何部署docker+rune+Occlum的运行环境。

首先开发者还是下载并运行occlum sdk容器镜像，在其中通过Occlum SDK开发和构建Enclave应用，并用ESK对Enclave Image进行签名，然后通过docker将Enclave应用只作为普通容器镜像，接下来通过标准docker等组件拉起容器镜像，最终调用rune启动Enclave容器并运行Occlum和Enclave应用。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713750472-b345da1b-81df-4b56-8127-4beb3c7e367f.png#alt=undefined)

最后是部署K8s的运行环境，这也是最新的Inclavare Containers 0.4.0支持的部署方式。

第一步还是开发者要下载并运行occlum sdk容器镜像，在其中通过Occlum SDK开发和构建Enclave应用，不同的是不再需要用ESK对Enclave Image进行签名了。后续步骤与前面的部署方式类似，但增加了sgx-device-plugin等K8s组件。这种部署方式适用于在云上部署机密计算集群，具体详细步骤请参考这里的链接。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713773292-0adc1c07-6d89-496f-ae75-df8fe8b2d9f9.png#alt=undefined)

让我们回顾整个演讲，我们识别出云原生场景下的数据安全威胁和风险，明确了机密计算这一解决问题的思路，并着手推进和实施ACK-TEE解决方案，最后剖析Inclavare Containers这一机密计算容器运行时技术。

总结起来，我们希望能够集中阿里云容器技术在业内的技术优势，持续打磨更易用、更安全、基于K8s的云原生机密计算集群产品ACK-TEE；同时，依托Inclavare Containers技术和生态，在支撑ACK-TEE产品的同时，也能向业界提供开源和标准化的Enclave容器技术；从战略角度来看，阿里云也将持续致力于在IaaS和PaaS层提供覆盖数据全生命周期的安全防护能力；因此，我们也将持续推进Inclavare Containers这一机密计算技术的发展，以及ACK-TEE产品的不断演进，助力阿里云成为提供机密计算能力的顶级云厂商。

![](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/230754/1596713788946-292548df-464f-4103-950f-fc7ef92aaca9.png#alt=undefined)

感谢大家。

为了圈内的小伙伴不走失，我们建立了交流群【Inclavare Containers技术讨论群】（钉钉群），邀请感兴趣的你加入。

关注「云巅论剑」，与我们一起发掘Linux相关内核技术，探索操作系统未来发展方向。

