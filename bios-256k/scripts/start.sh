SEABIOS_PARENT_DIR=${SEABIOS_PARENT_DIR:-/root/bios}
OUTPUT_DIR=${OUTPUT_DIR:-/root/output}
SEABIOS_DIRNAME=seabios
SEABIOS_GIT_REPO=https://git.qemu.org/git/seabios.git

ARTIFEST=bios.bin
ARTIFEST_BUILD_PATH=out
ARTIFEST_HASH=48772e82a2993f44894820637ce13e0aceb9ab68d3b01dab79c945eaaa2d74cf

REPORT_FILE=$OUTPUT_DIR/report
ARTIFEST_FILE=$OUTPUT_DIR/bios-256k.bin

info() {
    echo "[INFO]" $1
}

error() {
    echo "[ERROR]" $1
    exit -1
}

get_code() {
    cd $SEABIOS_PARENT_DIR
    [ ! -d "$SEABIOS_DIRNAME" ] && {
        info "Start clone seabios source code.."
        git clone $SEABIOS_GIT_REPO
    }

    cd $SEABIOS_DIRNAME
    git reset --hard 54082c81d96028ba8c76fbe6784085cf1df76b20
}

build() {
    cd $SEABIOS_PARENT_DIR/$SEABIOS_DIRNAME
    make clean && make
    mv $ARTIFEST_BUILD_PATH/$ARTIFEST $ARTIFEST_FILE
    info "Build done, artifest is $ARTIFEST"
}

analyze() {
    date=`TZ=UTC-8 date "+%Y-%m-%d %H:%M:%S"`
    echo "===bios-256k.bin RB Test===" > $REPORT_FILE
    echo "[Time] $date" >> $REPORT_FILE
    local sha256=`sha256sum $ARTIFEST_FILE | awk '{print $1}'`

    [ "$ARTIFEST_HASH" = "$sha256" ] && {
        echo "[Succeed] Same hash $sha256" >> $REPORT_FILE
    } || {
        echo "[Failed] Different hash $sha256, but RV is $ARTIFEST_HASH" >> $REPORT_FILE
    }
}

main() {
    get_code

    build 
    
    analyze
}

main "$@"