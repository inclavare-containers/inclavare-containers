# Reproducible Build Infrastructure

For convenience, some scripts are collected for automatically building.

## Files
*   `rbi.sh` main script. Use `./rbi.sh help` to see details.
*   `kata-agent/` scripts related to RB of kata-agent.
*   `rootfs-img` scripts and patches related to RB of rootfs raw disk image
*   `kernel` scripts related to RB of kernel
*   `in-toto` files about in-toto support software supply chain

## Instructions

### RB for kata-agent
Firstly, build RBCI(Reproducible Build Container Image) for kata-agent

```bash
./rbi.sh agent-image
```

Check the reproducibility of source code in `/path/to/kata-containers`.

```
./rbi.sh agent-local /path/to/kata-containers
```

Or, check the reproducibility of source code from github.com.

```bash
./rbi.sh agent-git
```
Above 2 operations can both produce a report and an artifest in `report/`.

Delete RBCI for kata-agent

```bash
./rbi.sh agent-image
```

Clean all tempfiles

```bash
./rbi.sh clean
```

### RB for kata-containers.img

Firstly, need to generate a root file system locally, then the rootfs
will be used to build a raw disk image.

```bash
./rbi.sh rootfs
```

And the rootfs will be in `result/rootfs/rootfs`.
Then, need a raw disk image using the rootfs
just generated. The img file will be `result/kata-containers.img`

```bash
./rbi.sh rootfs-image-build
```

Up to now, a rootfs's raw disk image is generated. Then, we need
to check whether the content is the same as expected.
Build a docker image which we use as a base environment to check 
the contents of a specific image file.
The image name is `rootfs-rdi-check`.

```bash
./rbi.sh rootfs-checker
```

Finally, check the content of the disk image generated
in 2. Compare them with the expected files using their hash 
values, and output a report in `report/rootfs/check-report`

```bash
./rbi.sh rootfs-check
```

(Optional) Also, the image `rootfs-rdi-check`  can be removed

```bash
./rbi.sh rootfs-rmi
```

### RB for kernel

```bash
./rbi.sh kernel-rbi
```
builds RBCI of kernel, named`kernel-rbci`

```
./rbi.sh kernel-build
```
rb kernel and generate report in `result/kernel`. 
Here, `result/kernel/vmlinux` is the kernel and 
`result/kernel/kernel_report` is the check report.

If correctly, you can get report as
```plaintext
$cat report/kernel_report 
===KERNEL RB REPORT===
[Time] 2021-07-23 17:58:59
[SUCCESSFUL] Same hash
```

### RB for bios-256k.bin

Firstly, build the RBCI of bios-256k.bin, named `bios-256k-rbci`.
```bash
./rbi.sh bios-rbi
```

Then, build bios-256k.bin, the artifest will be 
`result/bios/bios-256k.bin` and the report `result/bios/report`

```bash
./rbi.sh bios-build
```