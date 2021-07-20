# RB for rootfs

This repo aims to reproduce a rootfs based on centos-7

## Method

Original rootfs building, is by copying files from a docker container

Assign the yum packages specific version. Besides, after each build,
a report containing all the packages version will be given, helping 
debug.

## usage

`build.sh` is the main script. User should provide 5 parameters:
```bash
$ ./build.sh 
    
    This script aims to apply a patch to kata-containers v2.1-stable, 
    and run build_rootfs.sh to build a rootfs file system structure.
    Parameters:
        - <path/to/source_code_dir> source_code_dir means dir 
            'kata-containers'.
        - <path/to/output_dir> target dir of rootfs/ generated.
        - <path/to/patch> patch dir.
        - <path/to/kata-agent> kata-agent binary file.
        - <path/to/report-file> contains installed yum packages info.
```

If properly executed, you will get output like
```bash
[OK] Agent installed
INFO: Check init is installed
[OK] init is installed
INFO: Create /etc/resolv.conf file in rootfs if not exist
INFO: Creating summary file
INFO: Created summary file '/var/lib/osbuilder/osbuilder.yaml' inside rootfs
[INFO] Succeed! FS is generated in ./rootfs
A yum installed list is in report
Thank you :D
```