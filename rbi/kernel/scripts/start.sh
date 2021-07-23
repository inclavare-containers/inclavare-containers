#! /bin/bash
VERSION=5.10.25
KERNEL_DIR=${KERNEL_DIR-"/root/linux-${VERSION}"}
OUTPUT_DIR=${OUTPUT_DIR-"/root/output"}
CONFIG=.config
ARTIFEST=arch/x86/boot/bzImage

info() {
    echo "[INFO]" $1
}

info "Build kernel in $KERNEL_DIR"
cd $KERNEL_DIR
export INSTALL_MOD_STRIP=-s
export KBUILD_BUILD_TIMESTAMP=0
export KBUILD_BUILD_USER=root
export KBUILD_BUILD_HOST=localhost
make mrproper
make allnoconfig

echo -e '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n' | make -j4 ARCH=x86_64
info "Build done"
info "Artifest is bzImage"
cp $ARTIFEST $OUTPUT_DIR