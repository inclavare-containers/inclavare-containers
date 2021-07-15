#! /bin/bash

source_code_dir=$(cd $1; pwd)

GIT_REPO=https://github.com/kata-containers/kata-containers.git
REPO_NAME=kata-containers
KATA_VERSION=stable-2.1
PATCH_DIR=$(cd $(dirname "$0"); pwd)/patch
PROTOCOL_DIR=$source_code_dir/$REPO_NAME/src/agent/protocols

INFO="[INFO]"
ERROR="[ERROR]"

usage() {
    echo "This script aims to download kata-agent's source code from github.com"
    echo "Parameters"
    echo "- <path/to/save/code>"
    exit
}

download_code() {
    cd $source_code_dir
    if [ -d $REPO_NAME ]; then 
        echo "$INFO $REPO_NAME already exists, use it"
    else
        git clone $GIT_REPO
        if [ "$?" != 0 ]; then 
        echo "$ERROR Git clone failed."
            exit -1
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


