#! /bin/bash

# this script use to generate dir structure of a dir,
# together with every file in it with its sha256 value.

check_and_sum() {
    local input_dir=$1
    local output_file=$2

    cd $input_dir

    for file in $(find .) 
    do
        # echo $file
        [ -d $file ] && echo "dir $file" >> $output_file && continue
        sha256=$(sha256sum $file | awk {'print $1'})
        [ -f $file ] && echo "file $file $sha256" >> $output_file
    done
}

main() {
    local input_dir=$1
    local output_file=$2
    check_and_sum $input_dir $output_file
}

main "$@"