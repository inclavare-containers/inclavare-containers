# RB for linux kernel

## files
`build-docker-image.sh` To build RBCI for kernel

`get-source-code.sh` To get linux kernel code from kernel.org

`build-kernel.sh` To build kernel and check artifest

## Steps
`./build-docker-image.sh kernel-rbci` builds a docker image named`kernel-rbci`

`./get-source-code.sh ./linux` get source code of Linux to `./linux`

`./build-kernel.sh ./linux ./report` rb kernel and generate report

If correctly, you can get report as
```plaintext
$cat report/kernel_report 
===KERNEL RB REPORT===
[Time] 2021-07-23 17:58:59
[SUCCESSFUL] Same hash
```