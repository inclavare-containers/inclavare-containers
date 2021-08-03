# RB for linux kernel
## files
`build-docker-image.sh` To build RBCI for kernel
`build-kernel.sh` To build kernel and check artifest

## Steps
Build RBCI for kernel.
```
./build-docker-image.sh
```

rb kernel and generate report
```
./build-kernel.sh ../kata-agent/kata-containers ../result/kernel
``` 

If correctly, you can get report as
```plaintext
$cat report/kernel_report 
===KERNEL RB REPORT===
[Time] 2021-07-23 17:58:59
[SUCCESSFUL] Same hash
```