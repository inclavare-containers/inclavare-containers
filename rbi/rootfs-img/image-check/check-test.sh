#! /bin/bash

MBR_CFILE=mbr-checker.c

info() {
    echo "[INFO]" $1
}

error() {
    echo "[ERROR]" $1
    exit -1
}

usage() {
    cat << EOT
    
    This script aims to run raw disk image checker, to check whether 
    the contents of a image is the same as a reference file gives.
    
    Parameters:
        - <path/to/image file> s.t. raw disk image file
        - <path/to/output_dir> report file to output
        - <RBCI name>
EOT
    exit
}

exist_report() {
    local file_name=$1

    info "$file_name exists, cleaning..."
    rm -f $file_name
    info "$Clean done."
}

compare_mbr() {
    local disk_image=$1
    local script_dir=$2
    local checker=$script_dir/mbr-checker
    info "Compare MBR..."
    gcc $script_dir/$MBR_CFILE -O2 -o $checker

    $checker $disk_image
    [ "$?" != 0 ] && {
        rm -f $checker
        exit -1
    }
    rm -f $checker
}

run_build() {
    local raw_disk=$1
    local output_file=$2
    local image_name=$3
    local script_dir=$4

    local raw_disk_path=$(cd $(dirname $raw_disk);pwd)
    local raw_disk_name=${raw_disk##*/}
    local output_file_path=$(cd $(dirname $output_file);pwd)
    local output_file_name=${output_file##*/}

    compare_mbr $raw_disk_path/$raw_disk_name $script_dir

    info "Will launch a docker container to compare data\
        $raw_disk_path/$raw_disk_name"
    info "Results will be redirected to \
        $output_file_path/$output_file_name"

    sudo docker run -it --rm --privileged \
                        -v $raw_disk_path:/root/input \
                        -v $output_file_path:/root/output \
                        -v /dev:/dev \
                        --env IMAGE_FILE=/root/input/$raw_disk_name \
                        --env REPORT_FILE=/root/output/$output_file_name \
                        $image_name

    if [ "$?" != "0" ] ; then
        echo "$ERROR docker run failed"
        exit -1
    else 
        end_notify $output_file_path/$output_file_name
    fi
}

end_notify() {
    local output_file=$1

    cat <<EOT
[INFO] Check Done. A report is generated.
You can check it for details. Different files will
be recorded in the file $output_file
Enjoy yourself :P
EOT
}

main() {
    if [ -z $3 ]; then 
        usage
    fi

    local raw_disk_image=$1
    local report_file=$2
    local rbci_name=$3
    local script_dir=$(cd $(dirname $0); pwd)

    [ -f $report_file ] && exist_report $report_file

    run_build $raw_disk_image $report_file $rbci_name $script_dir
}

main "$@"