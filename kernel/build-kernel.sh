#! /bin/bash

source_code_dir=
output_dir=
abs_pwd=

ARTIFEST=vmlinux
REPORT_FILE=kernel_report
BUILD_DIR=tools/packaging/kernel
IMAGE=kernel-rbci

SHA256_KERNEL=f5c16c540d89b96b9a9040991d1646b46f90ec1a25fea42bd637dd978a41824b

usage() {
    cat << EOT
    
    This script aims to build a kernel of linux 5.10.25 for
    kata-containers.
    
    Parameters:
        - <path/to/source_code_dir> source_code_dir means dir 
            'kata-containers'
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

patch() {
    local abs_pwd=$1
    local abs_source_code_dir=$2

    echo "$INFO Apply patch from $abs_pwd/patch --> $abs_source_code_dir/$BUILD_DIR"
    cp -rf $abs_pwd/patch/* $abs_source_code_dir/$BUILD_DIR
    echo "$INFO Apply patch done."
}

run_build() {
    local abs_source_code_dir=$1
    local abs_output_dir=$2 

    info "Will began to build $abs_source_code_dir --> $abs_output_dir/$ARTIFEST"
    sudo docker run --rm -it \
                    -v $abs_source_code_dir:/root/kata-containers \
                    -v $abs_output_dir:/root/output \
                    --env KATA_REPO=/root/kata-containers \
                    --env OUTPUT_DIR=/root/output \
                    --env https_proxy=$https_proxy \
                    --network host \
                    $IMAGE
    
    [ "$?" != "0" ] && echo "$ERROR docker run failed" && exit -1
}

checksum() {
    local output_dir=$1

    artifest=$output_dir/$ARTIFEST
    report=$output_dir/$REPORT_FILE

    echo "===KERNEL RB REPORT===" > $report
    date=`TZ=UTC-8 date "+%Y-%m-%d %H:%M:%S"`
    echo "[Time] $date" >> $report

    sha256v=$(sha256sum $artifest | awk {'printf $1'})
    [ "$sha256v" == "$SHA256_KERNEL" ] && \
        echo "[SUCCESSFUL] Same hash" >> $report || \
        echo "[FAILED] Different hash, get $sha256v" >> $report
}

end_notify() {
    local output_dir=$1

    cat <<EOT
$INFO Build Done. Artifest is $output_dir/$ARTIFEST.
Report is $output_dir/$REPORT_FILE.
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

    [ -d $output_dir ] && exist_output_dir $output_dir || \
        no_exist_output_dir $output_dir

    local abs_source_code_dir=$(cd "$source_code_dir";pwd)
    local abs_output_dir=$(cd "$output_dir";pwd)
    
    patch $abs_pwd $abs_source_code_dir

    run_build $abs_source_code_dir $abs_output_dir

    checksum $abs_output_dir

    end_notify $abs_output_dir
}

main "$@"