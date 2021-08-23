#! /bin/bash

REPORT_FILE=.check_done

usage() {
    cat << EOT
    
    This script aims to check the integrity of some file.
    If it matches, there will be a file '.check_done'
    in the directory

    Parameters:
        - <path/to/file>
        - <expected sha256value> 
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

checksum() {
    local abs_file_dir=$1
    local file=$2
    local SHA256=$3

    file=$abs_file_dir/$file
    report=$abs_file_dir/$REPORT_FILE

    sha256v=$(sha256sum $file | awk {'printf $1'})
    [ "$sha256v" == "$SHA256" ] && \
        touch $report && exit 0
}

main() {
    if [ -z $2 ]; then 
        usage
    fi

    sha256=$2
    abs_pwd=$(cd $(dirname $0); pwd)
    abs_file_dir=$(cd $(dirname $1); pwd)
    rel_path=$1
    filename=${rel_path##*/}
    checksum $abs_file_dir $filename $sha256
    exit -1
}

main "$@"