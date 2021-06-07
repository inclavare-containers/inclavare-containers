---
title: "SGX in-tree驱动的内幕"
author: "乾越"
description: "由于upstream对SGX in-tree驱动的实现存在很多争议并引发了诸多讨论，其中较大的一个关于FLC的争议最终导致SGX in-tree驱动不得不放弃基于Lauch Control的launch enclave生成token”的机制。这里对这个故事背景进行一下复盘。"
categories: "Inclavare-containers"
tags: ["驱动","Inclavare Containers"]
date: 2020-08-12T15:00:00+08:00
cover: "/in-tree.png"
---

# 故事背景

众所周知，由于upstream对SGX in-tree驱动的实现存在很多争议并引发了诸多讨论，其中较大的一个关于FLC的争议最终导致SGX in-tree驱动不得不放弃基于Lauch Control的launch enclave生成token”的机制。这里对这个故事背景进行一下复盘。

事情出自[v22 SGX in-tree驱动](https://lkml.org/lkml/2019/9/3/636)。

Reviewer Borislav对作者的这段SGX Lauch Control特性的检测逻辑进行了“批判”：
```C
+static void __maybe_unused detect_sgx(struct cpuinfo_x86 *c)
+{
+   unsigned long long fc;
+
+   rdmsrl(MSR_IA32_FEATURE_CONTROL, fc);
+   if (!(fc & FEATURE_CONTROL_LOCKED)) {
+       pr_err_once("sgx: The feature control MSR is not locked\n");
+       goto err_unsupported;
+   }
+
+   if (!(fc & FEATURE_CONTROL_SGX_ENABLE)) {
+       pr_err_once("sgx: SGX is not enabled in IA32_FEATURE_CONTROL MSR\n");
+       goto err_unsupported;
+   }
+
+   if (!cpu_has(c, X86_FEATURE_SGX1)) {
+       pr_err_once("sgx: SGX1 instruction set is not supported\n");
+       goto err_unsupported;
+   }
+
+   if (!(fc & FEATURE_CONTROL_SGX_LE_WR)) {
+       pr_info_once("sgx: The launch control MSRs are not writable\n");
+       goto err_msrs_rdonly;
+   }
+
+   return;
+
+err_unsupported:
+   setup_clear_cpu_cap(X86_FEATURE_SGX);
+   setup_clear_cpu_cap(X86_FEATURE_SGX1);
+   setup_clear_cpu_cap(X86_FEATURE_SGX2);
+
+err_msrs_rdonly:
+   setup_clear_cpu_cap(X86_FEATURE_SGX_LC);
+}
```

可以看出，如果BIOS锁死了FEATURE_CONTROL_SGX_LE_WR位并且设为0的话，内核就无法写`MSR_IA32_SGXLEPUBKEYHASH{0, 1, 2, 3}`这四个寄存器，进而无法达成“内核控制Enclave的初始化和运行”这个目的；也就是说，加载和运行一个Enclave就需要持有合法的token才可以，而负责颁发token的Launch Enclave则可以制定自己的策略来决定是否给一个Enclave颁发token，这就是所谓的Launch Control机制。作者在这里针对这种情况，仅仅是清除了`X86_FEATURE_SGX_LC`特性位，而保留了SGX的其他特性。

但Reviewer发现了这个问题，并敏锐地提了出来：
![屏幕快照 2020-07-29 下午10.54.57.png](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/65684/1596034511819-0126d03a-6f02-4f65-820c-9f1dba76225c.png) 

然后作者开始摆事实讲道理：
![屏幕快照 2020-07-29 下午11.01.25.png](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/65684/1596034896165-20a48b36-33eb-4f24-80c6-930618fef80e.png) 

Reviewer依旧不依不饶，并且开始喷起BIOS是多么的“糟糕”（还有更糟糕的词汇，自己搜吧）：
![屏幕快照 2020-07-29 下午11.06.19.png](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/65684/1596035194249-19ab57d5-f146-469d-8211-3f15b4dbbd8b.png) 

好吧，这个决定导致从v25开始，如果处理器不支持FLC（包括SGX1这种完全不支持FLC的系统，以及虽然支持但BIOS把`X86_FEATURE_SGX_LC`特性位清0的系统），**所有SGX特性都将无法使用**。
```C
+update_sgx:
+   if (!cpu_has(c, X86_FEATURE_SGX) || !cpu_has(c, X86_FEATURE_SGX_LC)) {
+       clear_sgx_caps();
+   } else if (!(msr & FEAT_CTL_SGX_ENABLED) ||
+          !(msr & FEAT_CTL_SGX_LC_ENABLED)) {
+       if (IS_ENABLED(CONFIG_INTEL_SGX))
+           pr_err_once("SGX disabled by BIOS\n");
+       clear_sgx_caps();
+   }
```

好吧。其实reviewer的观点一开始就说了：
![屏幕快照 2020-07-29 下午11.06.45.png](https://intranetproxy.alipay.com/skylark/lark/0/2020/png/65684/1596035230224-57b6d185-a852-4f78-a5f1-786cc6ffc460.png) 

Linux以及开源社区一向反感各种lockdown和DRM，我印象中早些年Win7刚出来时强行默认开UEFI Secure Boot且BIOS setup中不提供关闭选项导致无法安装Linux，这让Linux社区震怒，最后社区和微软交涉才有了今天的shim bootloader（当然，终端用户不用自己去找微软签名bootloader，这是每个Linux发行版本自己找微软签名的事情了，而且这个默契也已经持续很久了）。

---

# 个人观点
对此我的观点是：务实。

首先，即使具备大量EPC内存的SGX2机器已经上线了，我们测试网内的开发机一般都是老旧淘汰机型，SGX1就属于这种，难道就只能用着不再维护的SGX OOT驱动了（OOT驱动支持没有FLC的SGX1机型）？

其次，况且现在SGX2机器还没有上线，样机也要晚些时候才ready，而目前我手上有很高优先级的任务需要做SGX in-tree驱动的适配，因此急需SGX in-tree驱动能够支持SGX1机型。

最后，在云场景中，对于云租户来说，即使CSP在BIOS里将Lauch Control锁定了，只要CSP在自己定制的Launch Enclave中确保合法的云租户能正常运行该租户自己签的enclave就可以了，其实这反倒是增加了一重保护。如果像现在SGX in-tree驱动的这种实现模式，等于任何非特权用户（包括成功入侵的攻击者）都可以任意运行自己编写的Enclave了（包括恶意Enclave）。

所以根据目前实际情况，我编写了两个补丁，希望能让目前在手头上不支持FLC的SGX1系统上能够运行SGX in-tree驱动，并基于该驱动实现自己需要的上层特性。

---

# 补丁使用方法
- 给[v33 SGX in-tree驱动代码](https://github.com/jsakkine-intel/linux-sgx/tree/v33)打上[SGX驱动patch](https://github.com/alibaba/inclavare-containers/blob/master/patch/no-sgx-flc/0001-sgx-Support-SGX1-machine-even-without-FLC-support.patch)
- 给[Intel SGX SDK 2.10源码](https://github.com/intel/linux-sgx/tree/sgx_2.10)打上[PSW patch](https://github.com/alibaba/inclavare-containers/blob/master/patch/no-sgx-flc/0001-psw-Support-SGX1-machine-with-SGX-in-tree-driver.patch)

---

# 补丁功能验证方法
在不支持FLC的SGX1机型上安装并运行打过patch的内核和aesm service。

- 能够成功运行[sgx-tools](https://github.com/alibaba/inclavare-containers/tree/master/sgx-tools#test)生成launch token

- 能够[用rune成功运行skeleton](https://github.com/alibaba/inclavare-containers/blob/master/rune/libenclave/internal/runtime/pal/skeleton/README.md)
  * 注意：运行skeleton之前，需要修改config.json： 
    ```
    "enclave.runtime.args": "no-sgx-flc"
    ```

目前我们已经在SGX1机型中成功部署了这种运行方式，并用于[Inclavare Containers开源项目](https://github.com/alibaba/inclavare-containers)的社区release测试中。

---

# 后续工作
- 希望能将PSW的patch推进到upstream中(还需要加入自动检测代码来动态设置no_sgx_flc这个flag)。
- 在用户态把FLC的检测做了，免去还要手动指定参数的麻烦。

---

# 参考
- [intel-sgx邮件列表](https://patchwork.kernel.org/project/intel-sgx/list/)
