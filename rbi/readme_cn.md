# 可重复构建测试平台

为了方便，做RBI测试，镜像构建等的脚本集合

## 文件说明
*   `rbi.sh` 脚本主入口了，具体的功能可以执行`./rbi.sh help`查看
*   `kata-agent/` 和kata-agent相关的镜像构建、执行测试、拉代码仓库等脚本  

## 操作说明
### kata-agent可重复构建

先构建RBCI
```bash
./rbi.sh agent-image
```
测试目录为`/path/to/kata-containers`源码的RB
```
./rbi.sh agent-local /path/to/kata-containers
```
测试git源码
```bash
./rbi.sh agent-git
```
上述两个命令，均将会以二进制文件+报告的形式将结果输出到`report`下
删除RBCI
```bash
./rbi.sh agent-image
```
清除所有临时文件
```bash
./rbi clean
```

### kata-containers.img的可重复构建

首先，在本地生成一个rootfs，这个rootfs根文件系统用来创建裸磁盘镜像。
```bash
./rbi.sh rootfs
```

生成的根文件系统位于`result/rootfs/rootfs`。

然后，利用刚才的根文件系统创建磁盘镜像，镜像位于
`result/kata-containers.img`
```bash
./rbi.sh rootfs-image-build
```

现在，磁盘镜像创建完毕了，然后需要检查是不是与我们设想的一致。首先为这个检查环境创建一个镜像，镜像名为`rootfs-rdi-check`。
```bash
./rbi.sh rootfs-checker
```

最后，检查刚才生成的磁盘镜像，产生的对比报告将位于
`report/rootfs/check-report`
```bash
./rbi.sh rootfs-check
```

### Linux内核的可重复构建

首先创建kernel的RBCI，名为`kernel-rbci`
```bash
./rbi.sh kernel-rbi
```

然后，下载kernel的代码，构建内核二进制文件，并且对齐完整性检查，
生成报告在`./result/linux/kernel_report`，二进制文件为`./result/linux/bzImage`，
这一系列操作将在下面这个脚本命令中一次性实现

```
./rbi.sh kernel-build
```

如果完整性校验通过，则可以看到报告如下
```plaintext
$cat report/kernel/kernel_report 
===KERNEL RB REPORT===
[Time] 2021-07-23 17:58:59
[SUCCESSFUL] Same hash
```

### Kata VM使用BIOS的可重复构建

首先，构建bios-256k.bin的RBCI，通常这个名字叫做`bios-256k-rbci`
```bash
./rbi.sh bios-rbi
```

然后，构建bios-256k.bin,产物是`result/bios/bios-256k.bin`，
另外有一个完整性校验报告`result/bios/report`，里面会记录当前产物哈希和
标准结果的对比结果。

```bash
./rbi.sh bios-build
```