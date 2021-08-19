#! /bin/bash

REPORT_FILE=.check_done

SHA256_KERNEL=f5c16c540d89b96b9a9040991d1646b46f90ec1a25fea42bd637dd978a41824b

usage() {
    cat << EOT
    
    This script aims to check the integrity of the 'vmlinux' file built 
    by build-kernel.sh. If it matches, there will be a file '.check_done'
    in the directory

    Parameters:
        - <path/to/vmlinux> 
EOT
    exit
}

info() {
    echo "[INFO] $1"
}

error() {
    echo "[ERROR] $1"
    exit
}

checksum() {
    local abs_vmlinux_dir=$1
    local file=$2

    vmlinux=$abs_vmlinux_dir/$file
    report=$abs_vmlinux_dir/$REPORT_FILE

    sha256v=$(sha256sum $vmlinux | awk {'printf $1'})
    [ "$sha256v" == "$SHA256_KERNEL" ] && \
        touch $report
}

main() {
    if [ -z $1 ]; then 
        usage
    fi

    abs_pwd=$(cd $(dirname $0); pwd)
    abs_vmlinux_dir=$(cd $(dirname $1); pwd)
    rel_path=$1
    filename=${rel_path##*/}
    checksum $abs_vmlinux_dir $filename
}

main "$@"