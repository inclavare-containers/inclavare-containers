#! /bin/bash

usage() {
    cat << EOT

    This script aims to build raw disk checker's RBCI(Reproducible 
    Build Container Image)
    Parameters:
        - <RBCI name>

EOT
    exit
}

main() {
    local dir=$(cd "$(dirname "$0")";pwd)
    if [ -z $1 ]; then 
        usage
    fi

    sudo docker build -t $1 $dir
    if [ "$?" = "0" ] ;then
        echo "[SUCCEED] Docker build succeed."
    else 
        echo "[FAILED] Docker build failed."
    fi
}

main "$@"