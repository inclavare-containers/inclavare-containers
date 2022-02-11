#! /bin/bash

IMAGE_NAME=kernel-rbci

usage() {
    cat << EOT
    This script aims to build kernel's RBCI(Reproducible Build Container Image)
    Which will be named 'kernel-rbci'
EOT
    exit
}

main() {
    local dir=$(cd "$(dirname "$0")";pwd)
    if [ ! -n $1 ]; then 
        usage
    fi

    sudo docker build -t $IMAGE_NAME $dir
    if [ "$?" = "0" ] ;then
        echo "[SUCCEED] Docker build succeed."
    else 
        echo "[FAILED] Docker build failed."
    fi
}

main "$@"