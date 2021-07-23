#! /bin/bash

KERNEL=linux-5.10.25
KERNEL_TARBALL=${KERNEL}.tar.xz
KERNEL_TARBALL_URL=https://www.kernel.org/pub/linux/kernel/v5.x/${KERNEL_TARBALL}


PATCH_DIR=$(cd $(dirname "$0"); pwd)/patch

usage() {
    cat << EOT
    This script aims to download linux-5.10.25's source code from kernel.org
    Parameters
        - <path/to/save/code>
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

download_code() {
    abs_source_code_dir=$1 
    source_code_dirname=$2

    cd $abs_source_code_dir
    [ ! -f "$KERNEL_TARBALL" ] && {
        info "download kernel..."
        curl --fail -OL $KERNEL_TARBALL_URL
        [ "$?" != "0" ] && error "Get tarball failed"
    } || {
        info "find $KERNEL_TARBALL"
    }
    tar xf $KERNEL_TARBALL
    mv $KERNEL $source_code_dirname
}

main() {
    [ -z "$1" ] && usage && exit
    source_code_dir=$1

    local abs_source_code_dir=$(cd $(dirname $1); pwd)
    local source_code_dirname=${source_code_dir##*/}

    [ -d "$abs_source_code_dir/$source_code_dirname" ] && \
        error "$abs_source_code_dir/$source_code_dirname exists"

    download_code $abs_source_code_dir $source_code_dirname
    info "Source code downloaded in $abs_source_code_dir/$source_code_dirname"
}

main "$@"