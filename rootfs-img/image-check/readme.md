# Raw Disk Image Content Checker

This repo aims to check whether a given raw disk image's content
is the same as we hope to be.

## Method

Using a docker container. In the container, the image will be 
mount to a certain temp directory. Then check the directory
both its structure and files.

## usage

`check-build-image.sh` is the script to build the container image.

`check-test.sh` main script. User should provide 3 parameters:
```bash
$ ./check-test.sh 
    
    This script aims to run raw disk image checker, to check whether 
    the contents of a image is the same as a reference file gives.
    
    Parameters:
        - <path/to/image file> s.t. raw disk image file
        - <path/to/output_dir> report file to output
        - <RBCI name>
```

If properly executed, you will get output like
```bash
...
[INFO] Check done.
[INFO] umount /tmp/osbuilder-mount-dir.ieNZ
[INFO] rmdir /tmp/osbuilder-mount-dir.ieNZ
[INFO] loseup /dev/loop10
[INFO] Check Done. A report will be in .
You can check it for details. Different files will
be recorded in the file .../report
Enjoy yourself :P
```

## other information
The reference directory structure and file hashes are in the file
`files/reference`, which will be used as default.