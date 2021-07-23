#! /bin/bash

IMAGE_FILE=${IMAGE_FILE-/root/kata-container.img}
REFERENCE_VALUE_FILE=${REFERENCE_VALUE_FILE-/root/reference}
REPORT_FILE=${REPORT_FILE-/root/report}
IMG_PATH=$(dirname $IMAGE_FILE)

info() {
    echo "[INFO]" $1
}

error() {
    echo "[ERROR]" $1
    exit -1
}

check_files() {
    local rootfs_dir=$1
    
    [ -f $REPORT_FILE ] && info "$REPORT_FILE exists, delete." \
        && rm -f $REPORT_FILE
        
    date=`TZ=UTC-8 date "+%Y-%m-%d %H:%M:%S"`

    echo "==FILE COMPARE REPORT==" > $REPORT_FILE
    echo "[Time] $date" >> $REPORT_FILE

    info "Check for required files..."
    local file_numbers=$(cat $REFERENCE_VALUE_FILE | wc -l)
    
    while read line
    do
        filetype=$(echo $line | awk {'print $1'})
        path=$(echo $line | awk {'print $2'})

        [ $filetype == "file" ] && {
            ref_hashv=$(echo $line | awk {'print $3'})
            target_file=$rootfs_dir/$path
            if [ ! -f $target_file ] ; then
                echo "No $path" >> $REPORT_FILE
                continue
            fi
            
            hashv=$(sha256sum $target_file | awk {'print $1'})
            if [ $hashv != $ref_hashv ]; then 
                echo "Different file $path" >> $REPORT_FILE
                continue
            fi
        }

        [ $filetype == "dir" ] && {
            target_dir=$rootfs_dir/$path
            if [ ! -d $target_dir ]; then
                echo "No $path" >> $REPORT_FILE
            fi
        }
    done < $REFERENCE_VALUE_FILE

    [ "$file_numbers" == "$(find | wc -l)" ] && info "Check done." && \
                    info "Check done." && exit
    
    # info "Check new files..."
    # cd $rootfs_dir
    # for file in $(find .)
    # do
    #     echo $file
    #     sleep 1
    #     local found=0
    #     local find_file_type=
    #     [ -f $file ] && find_file_type=file || find_file_type=dir

    #     while read line
    #     do
    #         path=$(echo $line | awk {'print $2'})
    #         filetype=$(echo $line | awk {'print $1'})
    #         [ "$path" == "$file" ] && \
    #             [ "$filetype" == "$find_file_type" ] && {
    #             found=1
    #             break
    #         }
    #     done < $REFERENCE_VALUE_FILE

    #     [ "$found" == "1" ] || echo "New file $file" >> $REPORT_FILE
    # done
    info "Check done." 
}

main() {
    cd $IMG_PATH
    device=$(losetup -P -f --show $IMAGE_FILE)
    partprobe -s $device > /dev/null
    info "Wait for 5 seconds..."
    sleep 5

    [ -b ${device}p1 ] || error "Loop device creation failed."

    dirname=$(mktemp -p /tmp -d osbuilder-mount-dir.XXXX)
    info "Created temp directory $dirname."

    mount ${device}p1 $dirname
    info "${device}p1 mounted to $dirname."

    info "Start to check files in $dirname."
    check_files $dirname
    
    info "umount $dirname"
    umount $dirname

    info "rmdir $dirname"
    rmdir $dirname

    info "loseup $device"
    losetup -d $device
}

main "$@"