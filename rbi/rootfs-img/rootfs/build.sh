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

info() {
    echo "[INFO] $1"
}

error() {
    echo "[ERROR] $1"
    exit -1
}

exist_output_dir() {
    error "$output_dir exists, please design a new dir."
}

no_exist_input_dir() {
    error "no this dir $source_code_dir."
}

no_kata_agent() {
    error "no kata-agent file $kata_agent_bin."
}

patch() {
    local patch_dir=$1
    local source_code_dir=$2
    info " patch from $patch_dir -> $source_code_dir/\
                                    $ROOTFS_PATCHED_DIR"
    cp -rf $patch_dir/* $source_code_dir/$ROOTFS_PATCHED_DIR
}

machine_id() {
    local file=$1
    info "Substitute machine-id file.."
    rm -f $file
    touch $file
    echo 6f43137764ba4b59b021088a772817cd > $file
    chmod 0444 $file
}

clean_java_ca_cache() {
    local cachefile=$1
    info "Clean java CA cache..."
    rm -f $cachefile
}

run_build() {
    local source_code_dir=$1
    local output_dir=$2
    local kata_agent=$3

    kata_agent_abs=$(cd $(dirname $kata_agent); pwd)/kata-agent

    info " Will run script $source_code_dir/$ROOTFS_BUILDER_SCRIPT"
    sudo USE_DOCKER=true AGENT_SOURCE_BIN=$kata_agent_abs AGENT_INIT=yes \
        "$source_code_dir/$ROOTFS_BUILDER_SCRIPT" $DISTRO
    [ "$?" != "0" ] && error "rootfs build failed." && exit -1

    mv $source_code_dir/$ROOTFS_DIR $output_dir
    machine_id $output_dir/etc/machine-id
    clean_java_ca_cache $output_dir/etc/pki/ca-trust/extracted/java/cacerts
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

    info " starting to build rootfs."
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