#! /bin/bash
usage() {
    echo "This script aims to build kata-agent's RBCI(Reproducible Build Container Image)"
    echo "Parameters"
    echo "- <RBCI name>"
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
