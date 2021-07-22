#! /bin/bash

ROOTFS_BUILDER_SCRIPT=tools/osbuilder/rootfs-builder/rootfs.sh
ROOTFS_PATCHED_DIR=tools/osbuilder/
ROOTFS_DIR=tools/osbuilder/rootfs-builder/rootfs-Centos

ARTIFEST=rootfs-Centos
DISTRO=centos
INFO=[INFO]
ERROR=[ERROR]

usage() {
    cat << EOT
    
    This script aims to apply a patch to kata-containers v2.1-stable, 
    and run build_rootfs.sh to build a rootfs file system structure.
    Parameters:
        - <path/to/source_code_dir> source_code_dir means dir 
            'kata-containers'.
        - <path/to/output_dir> target dir of rootfs/ generated.
        - <path/to/patch> patch dir.
        - <path/to/kata-agent> kata-agent binary file.
        - <path/to/report-file> contains installed yum packages info.
        
EOT
    exit
}

exist_output_dir() {
    echo "$ERROR $output_dir exists, please design a new dir."
    exit -1
}

no_exist_input_dir() {
    echo "$ERROR no this dir $source_code_dir."
    exit -1
}

no_kata_agent() {
    echo "$ERROR no kata-agent file $kata_agent_bin."
    exit -1
}

patch() {
    local patch_dir=$1
    local source_code_dir=$2
    echo "$INFO patch from $patch_dir -> $source_code_dir/\
                                    $ROOTFS_PATCHED_DIR"
    cp -rf $patch_dir/* $source_code_dir/$ROOTFS_PATCHED_DIR
}

run_build() {
    local source_code_dir=$1
    local output_dir=$2
    local kata_agent=$3

    kata_agent_abs=$(cd $(dirname $kata_agent); pwd)/kata-agent
    
    echo "$INFO Will run script $source_code_dir/$ROOTFS_BUILDER_SCRIPT"
    sudo USE_DOCKER=true AGENT_SOURCE_BIN=$kata_agent_abs $source_code_dir/$ROOTFS_BUILDER_SCRIPT $DISTRO
    [ "$?" != "0" ] && echo "$ERROR rootfs build failed." && exit -1

    mv $source_code_dir/$ROOTFS_DIR $output_dir
}

report() {
    local output_dir=$1
    local report_dir=$2

    mv $output_dir/yum_installed $report_dir
}

end_notify() {
    local output_dir=$1
    local report_dir=$2

    cat <<EOT
$INFO Succeed! FS is generated in $output_dir
A yum installed list is in $report_dir
Thank you :D
EOT
}

main() {
    if [ -z $5 ]; then 
        usage
    fi

    echo "$INFO starting to build rootfs."
    source_code_dir=$1
    output_dir=$2
    patch_dir=$3
    kata_agent_bin=$4
    report_dir=$5

    [ -f $kata_agent_bin ] || no_kata_agent

    [ -d $output_dir ] && exist_output_dir || mkdir $(dirname $output_dir)
    
    [ -d $source_code_dir ] || no_exist_input_dir
    
    source_code_dir=$(cd $source_code_dir; pwd)

    patch $patch_dir $source_code_dir

    run_build $source_code_dir $output_dir $kata_agent_bin

    report $output_dir $report_dir

    end_notify $output_dir $report_dir
}

main "$@"