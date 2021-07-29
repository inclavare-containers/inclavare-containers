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
    tar_store_dir=$1 
    source_code_dirname=$2

    cd $tar_store_dir
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
    local source_code_dir=$(dirname $1)
    local source_code_dirname=${1##*/}

    local abs_target_dir=$source_code_dir/$source_code_dirname
    mkdir -p $source_code_dir

    [ -d "$abs_target_dir" ] && {
        [ "`cd $abs_target_dir; ls`" != "" ] && \
        error "$abs_target_dir is not empty" ||
        rmdir $abs_target_dir
    }

    download_code $source_code_dir $source_code_dirname
    info "Source code downloaded in $source_code_dir/$source_code_dirname"
}

main "$@"