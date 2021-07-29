#! /bin/bash

source_code_dir=
output_dir=
abs_pwd=

ARTIFEST=bzImage
REPORT_FILE=kernel_report

SHA256_KERNEL=dc27076f459308ced130956fc2ed078ade0fd1ac2a377c1b9b4ebfce990fcfae

usage() {
    cat << EOT
    
    This script aims to build a kernel of linux 5.10.25 for
    kata-containers, using RBI.
    
    Parameters:
        - <path/to/kernel_source> 
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
    sudo docker run --rm -it -v $abs_source_code_dir:/root/kernel \
                    -v $abs_output_dir:/root/output \
                    --env KERNEL_DIR=/root/kernel \
                    kernel-rbi
    
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
        echo "[FAILED] Different hash" >> $report
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
    [ ! -d "$source_code_dir" ] && error "$source_code_dir doesn't exist"
    local abs_source_code_dir=$(cd "$source_code_dir";pwd)
    local abs_output_dir=$(cd "$output_dir";pwd)
    local abs_rootfs_dir=$(cd "$rootfs_dir";pwd)

    [ -d $abs_output_dir ] && exist_output_dir $abs_output_dir \
            || no_exist_output_dir $abs_output_dir

    run_build $abs_source_code_dir $abs_output_dir

    checksum $abs_output_dir

    end_notify $abs_output_dir
}

main "$@"