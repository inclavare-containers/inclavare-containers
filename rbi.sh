#! /bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KATA=$SCRIPT_DIR/kata-agent
KATA_DIR=kata-containers
KATA_SOURCE_CODE_GETTER=$KATA/kata-source-code.sh
KATA_AGENT_TEST_SCRIPT=$KATA/kata-test.sh
KATA_AGENT_RBCI_NAME=kata-agent-rbci

KATA_AGENT_PATCH=$KATA/patch
KATA_AGENT_SCRIPT=$KATA/scripts
KATA_AGENT_BUILD_SCRIPT=$KATA/kata-build-docker.sh
KATA_AGENT_TESTER=$KATA/kata-test.sh

RAW_DISK_BUILDER=$SCRIPT_DIR/rootfs-img
ROOTFS_BUILDER_DIR=$RAW_DISK_BUILDER/rootfs
ROOTFS_BUILDER=$ROOTFS_BUILDER_DIR/build.sh
ROOTFS_BUILDER_PATCH=$ROOTFS_BUILDER_DIR/patch
ROOT_IMAGE_BUILDER=$RAW_DISK_BUILDER/image
ROOT_IMAGE_BUILDER_SCRIPT=$ROOT_IMAGE_BUILDER/build-img.sh
ROOTFS_RRDCI_NAME=rootfs-rdi-check
ROOTFS_CHECKER_DIR=$RAW_DISK_BUILDER/image-check
ROOTFS_CHECKER_BUILDER_SCRIPT=$ROOTFS_CHECKER_DIR/check-build-image.sh
ROOTFS_CHECKER_SCRIPT=$ROOTFS_CHECKER_DIR/check-test.sh

RESULT_DIR=$SCRIPT_DIR/result
KATA_AGENT_ARTIFEST=$RESULT_DIR/kata-agent
ROOTFS_OUTPUT=$RESULT_DIR/rootfs
ROOTFS_OUTPUT_DIR=$ROOTFS_OUTPUT/rootfs
ROOTFS_OUTPUT_REPORT=$ROOTFS_OUTPUT/rootfs-report
RAW_DISK_IMAGE=$ROOTFS_OUTPUT/kata-containers.img
RAW_DISK_CHECK_REPORT=$ROOTFS_OUTPUT/check-report

KERNEL_IMAGE=kernel-rbci
KERNEL_IMAGE_BUILDER=$SCRIPT_DIR/kernel/build-docker-image.sh
KERNEL_BUILDER=$SCRIPT_DIR/kernel/build-kernel.sh
KERNEL_SOURCE_CODE_SCRIPT=$SCRIPT_DIR/kernel/get-source-code.sh
KERNEL_SOURCE_DIR=$KATA/$KATA_DIR
KERNEL_OUTPUT_DIR=$RESULT_DIR/kernel

BIOS_IMAGE=bios-256k-rbci
BIOS_IMAGE_BUILDER=$SCRIPT_DIR/bios-256k/build-docker-image.sh
BIOS_CODE_DIR=$SCRIPT_DIR/bios-256k
BIOS_BUILDER=$SCRIPT_DIR/bios-256k/build-bios.sh
BIOS_OUTPUT=$RESULT_DIR/bios

usage()
{
	error="${1:-0}"
	cat <<EOT

Usage: ${script_name} [options]

Build RBCI, run RB tests for different components.

Tips:
  [[ kata-agent build & test ]]
  1. agent-image - Generate kata-agent RBCI to build source code 
    into binary. The image is named 'kata-agent-rbci'.
  2. agent-git/agent-local - Build a binary using RBCI in 1, and
    calculate the artifest's sha256 hash value to compare with 
    the reference value. Finally, output a report in the path 
    'result/kata-agent/report', together with the binary 
    'result/kata-agent/kata-agent'.
  (Optional) 3. Delete RBCI if need.

  [[ rootfs raw disk image build & test ]]
  1. rootfs - Generate a root file system locally, then the rootfs
    will be used to build a raw disk image.
    The rootfs will be in 'result/rootfs/rootfs'
  2. rootfs-image-build - Build a raw disk image using the rootfs
    generated in 1. The img file will be 'result/kata-containers.img'
    Up to now, a rootfs's raw disk image is generated. Then, we need
    to check whether the content is the same as expected.
  3. rootfs-checker - Build a docker image which we use as a base
    environment to check the contents of a specific image file.
    The image name is 'rootfs-rdi-check'.
  4. rootfs-check - Check the content of the disk image generated
    in 2. Compare them with the expected files using their hash 
    values, and output a report in report/rootfs/check-report
  (Optional) 5. rootfs-rmi - Delete image generated in 3, s.t.
    'rootfs-rdi-check'.

  [[ linux kernel build & test ]]
  1. kernel-rbi - Create a RBCI of linux kernel. The name of the
    docker image will be kernel-rbci.
  2. kernel-code - Download linux kernel 5.10.25's source code in
    directory 'result/kernel'.
  3. kernel-build - Build kernel, the artifest will be 
    'result/kernel/bzImage' and the report 'result/kernel/kernel_report'

  or you may want to use a single cmd to build kernel, just use
  'kernel'

  [[ bios-256k.bin build & test ]]
  1. bios-rbi - Create a RBCI of bios-256k.bin. The name of the
    docker image will be bios-256k-rbci.
  2. bios-build - Build bios-256k.bin, the artifest will be 
    'result/bios/bios-256k.bin' and the report 'result/bios/report'

Options:
  help              Show this help message.
  agent             Generate kata-agent file.
  agent-git         Do kata-agent reproducible build test, pull source code
                    from github.
  agent-local <path/to/code>     
                    Do kata-agent reproducible build test, assign a path to
                    source code.
  agent-image       Make kata-agent's RBI.
  agent-rmi         Remove agent RBCI.
  
  rootfs            Make rootfs.
                    For options related to rootfs, the script will treat
                    path to kata-containers as 'kata-agent/kata-containers'.
  rootfs-image-build 
                    Make a raw disk image of rootfs.
  rootfs-checker    Make rootfs raw disk checker image(RRDCI)' RBI.
  rootfs-rmi        Remove rootfs raw disk checker image(RRDCI)' RBI.
  rootfs-check      Check a rootfs raw disk image's content.
  
  kernel            Generate kernel file.
  kernel-rbi        Make linux kernel's RBCI.
  kernel-build      Build linux kernel and check artifest's sha256 hash.

  bios              Generate BIOS file.
  bios-rbi          Make bios-256k.bin's RBCI, named 'bios-256k-rbci'.
  bios-build        Build bios-256k.bin, using image 'bios-256k-rbci'.

  clean-all         Clean all temp files, including kata-containers repo.
  clean             Clean temp files, except kata-containers repo.

EOT
exit "$error"
}

info() {
    echo "[INFO]" $1
}

error() {
    echo "[ERROR]" $1
    exit -1
}

agent() {
    info "Get kata source code from github.com"
    $KATA_SOURCE_CODE_GETTER $KATA
    if [ "$?" != 0 ]; then
        error "Can not get source code."
    fi

    info "Build RBCI..."

    image_already=`sudo docker images| grep $KATA_AGENT_RBCI_NAME | awk {'print $1'}`
    if [ "$image_already" != "$KATA_AGENT_RBCI_NAME" ]; then
        info "Build docker image for kata-agent RBC"
        $KATA_AGENT_BUILD_SCRIPT $KATA_AGENT_RBCI_NAME
    fi
    
    info "Run reproducible for kata agent"
    $KATA_AGENT_TESTER $KATA/$KATA_DIR $KATA_AGENT_ARTIFEST $KATA_AGENT_RBCI_NAME
}

test_agent_git() {
    info "Get kata source code from github.com"
    $KATA_SOURCE_CODE_GETTER $KATA
    if [ "$?" != 0 ]; then
        error "Can not get source code."
    fi
    info "Run reproducible test for kata agent"
    $KATA_AGENT_TESTER $KATA/$KATA_DIR $KATA_AGENT_ARTIFEST $KATA_AGENT_RBCI_NAME
}

test_agent_local() {
    local local_dir=$1
    if [ -z $1 ]; then
        usage
        exit -1
    fi
    info "Run reproducible test for kata agent locally"
    $KATA_AGENT_TESTER $local_dir $KATA_AGENT_ARTIFEST $KATA_AGENT_RBCI_NAME
}

build_agent_image() {
    image_already=`sudo docker images| grep $KATA_AGENT_RBCI_NAME | awk {'print $1'}`
    if [ "$image_already" = "$KATA_AGENT_RBCI_NAME" ]; then
        info "Detected image already exists, deleting it.."
        rm_agent_image
    fi
    info "Build docker image for kata-agent rbc"
    $KATA_AGENT_BUILD_SCRIPT $KATA_AGENT_RBCI_NAME
}

rm_agent_image() {
    sudo docker rmi $KATA_AGENT_RBCI_NAME
}

make_rootfs() {
    local kata_repo=$KATA/$KATA_DIR
    local output_dir=$ROOTFS_OUTPUT_DIR
    local kata_agent=$KATA_AGENT_ARTIFEST/$KATA
    local report_file=$ROOTFS_OUTPUT_REPORT

    info "Building rootfs. kata-containers repo from $kata_repo \
         rootfs will be put at $output_dir \
         using kata-agent from $kata_agent \
         a report will be $report_file"

    $ROOTFS_BUILDER $kata_repo \
                    $output_dir \
                    $ROOTFS_BUILDER_PATCH \
                    $kata_agent \
                    $report_file

    [ "$?" == "0" ] && info "Done" || error "rootfs make failed."
}

make_rootfs_image() {
    local kata_repo=$KATA/$KATA_DIR

    info "Start to build raw disk image \
        using kata-containers repo $kata_repo \
        from $ROOTFS_OUTPUT_DIR \
        to $ROOTFS_OUTPUT "

    $ROOT_IMAGE_BUILDER_SCRIPT $kata_repo \
                            $ROOTFS_OUTPUT_DIR \
                            $ROOTFS_OUTPUT
    [ "$?" == "0" ] && info "Done" || \
        error "raw disk image make failed."
}

build_rootfs_checker_image() {
    image_already=`sudo docker images| grep $ROOTFS_RRDCI_NAME | awk {'print $1'}`
    if [ "$image_already" = "$ROOTFS_RRDCI_NAME" ]; then
        info "Detected image already exists, deleting it.."
        rm_rootfs_checker_image
    fi
    info "Build docker image for rootfs's raw disk checker rbc"
    $ROOTFS_CHECKER_BUILDER_SCRIPT $ROOTFS_RRDCI_NAME
}

rm_rootfs_checker_image() {
    sudo docker rmi $ROOTFS_RRDCI_NAME
}

check_rootfs_img() {
    info "Run check in a docker container.."
    info "Check $RAW_DISK_IMAGE \
        Report will be $RAW_DISK_CHECK_REPORT"
    $ROOTFS_CHECKER_SCRIPT $RAW_DISK_IMAGE \
                        $RAW_DISK_CHECK_REPORT \
                        $ROOTFS_RRDCI_NAME
}

kernel() {
    info "Build RBCI..."

    image_already=`sudo docker images| grep $KERNEL_IMAGE | awk {'print $1'}`
    if [ "$image_already" != "$KERNEL_IMAGE" ]; then
        info "Build docker image for kernel RBC"
        $KERNEL_IMAGE_BUILDER $KERNEL_IMAGE
    fi
    
    info "Get kata-containers code..."
    $KATA_SOURCE_CODE_GETTER $KATA
    if [ "$?" != 0 ]; then
        error "Can not get source code."
    fi

    kernel_build
}

kernel_rbi() {
    image_already=`sudo docker images| grep $KERNEL_IMAGE | awk {'print $1'}`
    if [ "$image_already" = "$KERNEL_IMAGE" ]; then
        info "Detected image already exists."
        exit
    fi
    info "Build docker image for kernel RBC"
    $KERNEL_IMAGE_BUILDER $KERNEL_IMAGE
}

kernel_build() {
    info "Build kernel..."
    $KERNEL_BUILDER $KERNEL_SOURCE_DIR $KERNEL_OUTPUT_DIR
}

bios() {
    bios_rbi

    bios_build
}

bios_rbi() {
    image_already=`sudo docker images| grep $BIOS_IMAGE | awk {'print $1'}`
    if [ "$image_already" = "$BIOS_IMAGE" ]; then
        info "Detected image already exists."
        exit
    fi

    info "Build docker image for kernel RBC"
    $BIOS_IMAGE_BUILDER
}

bios_build() {
    info "Build BIOS..."
    $BIOS_BUILDER $BIOS_CODE_DIR $BIOS_OUTPUT
}

clean() {
    info "Cleaning all the temp files.." 
    rm -rf $RESULT_DIR
    info "Done." 
}

clean_all() {
    info "Cleaning $KATA/$KATA_DIR..."
    rm -rf $KATA/$KATA_DIR
    info "Done"
}

main() {
    local feature=$1
    case $feature in
    agent)
        agent
        ;;
    agent-git)
        test_agent_git
        ;;
    agent-local)
        test_agent_local $2
        ;;
    agent-image)
        build_agent_image
        ;;
    agent-rmi)
        rm_agent_image
        ;;
    rootfs)
        make_rootfs
        ;;
    rootfs-image-build)
        make_rootfs_image
        ;;
    rootfs-checker)
        build_rootfs_checker_image
        ;;
    rootfs-rmi)
        rm_rootfs_checker_image
        ;;
    rootfs-check)
        check_rootfs_img
        ;;
    kernel)
        kernel
        ;;
    kernel-rbi)
        kernel_rbi
        ;;
    kernel-build)
        kernel_build
        ;;
    bios)
        bios
        ;;
    bios-rbi)
        bios_rbi
        ;;
    bios-build)
        bios_build
        ;;
    clean)
        clean
        ;;
    clean-all)
        clean_all
        ;;
    help)
        usage
        ;;
    *)
        usage
        ;;
    esac
}

main "$@"