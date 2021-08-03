#! /bin/bash

VERSION=5.10.25
KATA_REPO=${KATA_REPO:-"/root/kata-containers"}
OUTPUT_DIR=${OUTPUT_DIR:-"/root/output"}

PACKING_DIR=$KATA_REPO/tools/packaging/kernel
BUILD_SCRIPT=$PACKING_DIR/build-kernel.sh
KERNEL_DIR=$PACKING_DIR/kata-linux-$VERSION-85

ARTIFEST=$KERNEL_DIR/vmlinux

info() {
    echo "[INFO]" $1
}

info "Build kernel in $PACKING_DIR"
cd $PACKING_DIR

info "Reset time.."
rm -f /etc/localtime
date
info "Setting up..."
bash $BUILD_SCRIPT setup

info "Build..."
bash $BUILD_SCRIPT build

mv $ARTIFEST $OUTPUT_DIR