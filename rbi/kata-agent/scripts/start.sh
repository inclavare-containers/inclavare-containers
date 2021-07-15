#! /bin/bash
SRC_DIR=/root/input/src/agent
ARTIFEST=$SRC_DIR/target/x86_64-unknown-linux-musl/release/kata-agent
OUTPUT_DIR=/root/output

REPORT_FILE=$OUTPUT_DIR/report

ARTIFEST_HASH=81de8efd8475c7413c5cf16066b6e023bcea6c3cd52c2984ff36b3dd69b855ff
ERROR="[ERROR]"
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
        echo "$ERROR Build failed."
        exit -1
    fi
    analyze $ARTIFEST $ARTIFEST_HASH $REPORT_FILE
    mv $ARTIFEST $OUTPUT_DIR
}

main "$@"