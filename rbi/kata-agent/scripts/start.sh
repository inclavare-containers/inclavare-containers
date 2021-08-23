#! /bin/bash

SRC_DIR=/root/input/src/agent
ARTIFEST=$SRC_DIR/target/x86_64-unknown-linux-musl/release/kata-agent
OUTPUT_DIR=/root/output

REPORT_FILE=$OUTPUT_DIR/report

ARTIFEST_HASH=11c8d799173ef309e1117471ca9d3d4d6ce495fda3e3d3ca00fff77439ce2d52

error() {
    echo "[ERROR]" $1
    exit -1
}

analyze() {
    local report_file=$3
    local artifest_hash=$2
    local artifest=$1
    date=`TZ=UTC-8 date "+%Y-%m-%d %H:%M:%S"`
    echo "===Agent RB Test===" > $report_file
    echo "[Time] $date" >> $report_file
    local sha256=`sha256sum $artifest | awk '{print $1}'`

    if [ "$artifest_hash" = "$sha256" ] ; then
        echo "[Succeed] Same hash $sha256" >> $report_file
    else
        echo "[Failed] Different hash $sha256, but RV is $artifest_hash" >> $report_file
    fi
}

main() {
    cd $SRC_DIR
    make clean && make
    if [ "$?" != 0 ]; then
        error "Build failed."
    fi
    analyze $ARTIFEST $ARTIFEST_HASH $REPORT_FILE
    mv $ARTIFEST $OUTPUT_DIR
}

main "$@"