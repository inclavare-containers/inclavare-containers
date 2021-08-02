#! /bin/bash

# this script use to generate dir structure of a dir,
# together with every file in it with its sha256 value.

usage() {
    cat << EOT

    This script use to generate dir structure of a dir,
    together with every file in it with its sha256 value.
    
    Parameters:
        - <path/to/dir> path to the directory to be analyzed.
        - <path/to/output/file> file to output.
    
    Extra Informations:

        output format will be like 
        \`\`\`
        ...
        dir <some/dir/name>
        file <some/file/name> <sha256>
        ...
        \`\`\`
EOT
    exit
}

check_and_sum() {
    local input_dir=$1
    local output_file=$2
    abs_output_file=$(cd $(dirname $output_file); pwd)/${output_file##*/}
    cd $input_dir

    for file in $(find . | sort) 
    do
        # echo $file
        [ -d $file ] && echo "dir $file" >> $abs_output_file && continue
        sha256=$(sha256sum $file | awk {'print $1'})
        [ -f $file ] && echo "file $file $sha256" >> $abs_output_file
    done
}

main() {
    [ -z $2 ] && usage && exit -1

    local input_dir=$1
    local output_file=$2
    check_and_sum $input_dir $output_file
}

main "$@"