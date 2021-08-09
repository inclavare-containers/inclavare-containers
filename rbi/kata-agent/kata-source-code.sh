#! /bin/bash

source_code_dir=$(cd $1; pwd)

GIT_REPO=https://github.com/kata-containers/kata-containers.git
REPO_NAME=kata-containers
KATA_VERSION=stable-2.1
PATCH_DIR=$(cd $(dirname "$0"); pwd)/patch
PROTOCOL_DIR=$source_code_dir/$REPO_NAME/src/agent/protocols

info() {
    echo "[INFO]" $1
}

error() {
    echo "[ERROR]" $1
    exit -1
}

usage() {
    cat << EOT

    This script aims to download kata-agent's source code from github.com
    Parameters
        - <path/to/save/code>
EOT
    exit
}

download_code() {
    cd $source_code_dir
    if [ -d $REPO_NAME ]; then 
        info "$REPO_NAME already exists, use it"
    else
        git clone $GIT_REPO
        if [ "$?" != 0 ]; then 
            error "Git clone failed."
        fi
    fi
}

checkout_patch() {
    cd $source_code_dir/$REPO_NAME
    git checkout $KATA_VERSION
    echo "$INFO Patch from $PATCH_DIR to $PROTOCOL_DIR"
    cp -rf $PATCH_DIR/* $PROTOCOL_DIR
}

main() {
    download_code

    checkout_patch
}

main "$@"