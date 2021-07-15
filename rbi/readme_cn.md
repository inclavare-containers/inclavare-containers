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