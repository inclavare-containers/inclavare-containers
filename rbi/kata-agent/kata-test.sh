#! /bin/bash

source_code_dir=$1
output_dir=$2
image_name=$3

ARTIFEST=kata-agent
REPORT_FILE=report

INFO=[INFO]
ERROR=[ERROR]

usage() {
    cat << EOT
    
    This script aims to run the kata-agent's RBCI(Reproducible Build Container Image)
    to check whether the source code proveded can be built into the correct artifest
    Parameters:
        - <path/to/source_code_dir> source_code_dir means dir 'kata-containers'
        - <path/to/output_dir>
        - <RBCI name>
EOT
    exit
}

exist_output_dir() {
    echo "$INFO $output_dir exists, cleaning contents..."
    rm -f $output_dir/$REPORT_FILE
    rm -f $output_dir/$ARTIFEST
    echo "$INFO Clean done."
}

no_exist_output_dir() {
    echo "$INFO $output_dir doesn't exist, creating.."
    mkdir -p $output_dir
    echo "$INFO $output_dir created."
}

run_build() {
    echo "$INFO Will launch a docker container to build $source_code_dir --> $output_dir"
    local abs_source_code_dir=$(cd "$source_code_dir";pwd)
    local abs_output_dir=$(cd "$output_dir";pwd)
    sudo docker run -it --rm \
                --env HTTPS_PROXY=$https_proxy \
                --network host \
                -v $abs_source_code_dir:/root/input -v $abs_output_dir:/root/output $image_name
    if [ "$?" != "0" ] ; then
        echo "$ERROR docker run failed"
        exit -1
    else 
        end_notify
    fi

    
}

end_notify() {
    cat <<EOT
$INFO Build Done. Artifests and a report will be in $output_dir.
You can check for details. 
Thank you :P
EOT
}

main() {
    if [ -z $2 ]; then 
        usage
    fi

    if [ -d $output_dir ]; then
        exist_output_dir
    else 
        no_exist_output_dir
    fi

    run_build
}

main "$@"