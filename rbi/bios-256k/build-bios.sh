#! /bin/bash

source_code_dir=
output_dir=
abs_pwd=

ARTIFEST=vmlinux
REPORT_FILE=bios_report
ARTIFEST=bios-256k.bin
IMAGE_NAME=bios-256k-rbci

usage() {
    cat << EOT
    
    This script aims to build bios-256k for kata-containers.
    
    Parameters:
        - <path/to/source_code_dir> path to save code for seabios.
            If it is already downloaded, this should be the parent
            path of the dir 'seabios'.
        - <path/to/output_dir> 
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

exist_output_dir() {
    local abs_output_dir=$1
    info "$INFO $abs_output_dir exists, cleaning contents..."
    rm -f $abs_output_dir/$REPORT_FILE
    rm -f $abs_output_dir/$ARTIFEST
    info "$INFO Clean done."
}

no_exist_output_dir() {
    local abs_output_dir=$1
    info "$abs_output_dir doesn't exist, creating.."
    mkdir -p $abs_output_dir
    info "$abs_output_dir created."
}

run_build() {
    local abs_source_code_dir=$1
    local abs_output_dir=$2 

    info "Will began to build $abs_source_code_dir --> $abs_output_dir/$ARTIFEST"
    sudo docker run --rm -it \
                    -v $abs_source_code_dir:/root/bios \
                    -v $abs_output_dir:/root/output \
                    --env SEABIOS_PARENT_DIR=/root/bios \
                    --env OUTPUT_DIR=/root/output \
                    --env https_proxy=$https_proxy \
                    --network host \
                    $IMAGE_NAME
    
    [ "$?" != "0" ] && echo "$ERROR docker run failed" && exit -1
}

end_notify() {
    local output_dir=$1

    cat <<EOT
$INFO Build Done. Artifest is $output_dir/$ARTIFEST
Report is $output_dir/$REPORT_FILE
You can check for details. 
Thank you :P
EOT
}

main() {
    if [ -z $2 ]; then 
        usage
    fi

    abs_pwd=$(cd $(dirname $0); pwd)
    source_code_dir=$1
    output_dir=$2

    [ -d "$output_dir" ] && exist_output_dir $output_dir || \
                no_exist_output_dir $output_dir

    local abs_source_code_dir=$(cd "$source_code_dir";pwd)
    local abs_output_dir=$(cd "$output_dir";pwd)

    run_build $abs_source_code_dir $abs_output_dir

    end_notify $abs_output_dir
}

main "$@"