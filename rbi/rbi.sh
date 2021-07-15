#! /bin/bash

KATA=kata-agent
KATA_DIR=kata-containers
KATA_SOURCE_CODE_GETTER=$KATA/kata-source-code.sh
KATA_AGENT_TEST_SCRIPT=$KATA/kata-test.sh
KATA_AGENT_RBCI_NAME=kata-agent-rbci

KATA_AGENT_PATCH=$KATA/patch
KATA_AGENT_SCRIPT=$KATA/scripts
KATA_AGENT_BUILD_SCRIPT=$KATA/kata-build-docker.sh
KATA_AGENT_TESTER=$KATA/kata-test.sh

RESULT_DIR=result
KATA_AGENT_ARTIFEST=$RESULT_DIR/$KATA

ERROR="[ERROR]"
INFO="[INFO]"

usage()
{
	error="${1:-0}"
	cat <<EOT

Usage: ${script_name} [options]

Build RBCI, run RB tests for different components.

Options:
  help              Show this help message.
  agent-git         Do kata-agent reproducible build test, pull source code
                    from github.
  agent-local <path/to/code>     
                    Do kata-agent reproducible build test, assign a path to
                    source code.
  agent-image       Make kata-agent's RBI.
  agent-rmi         Remove agent RBCI.

EOT
exit "$error"
}

test_agent_git() {
    echo "$INFO Get kata source code from github.com"
    ./$KATA_SOURCE_CODE_GETTER $KATA
    if [ "$?" != 0 ]; then
        echo "$ERROR Can not get source code."
        exit -1
    fi
    echo "$INFO Run reproducible test for kata agent"
    ./$KATA_AGENT_TESTER $KATA/$KATA_DIR $KATA_AGENT_ARTIFEST $KATA_AGENT_RBCI_NAME
}

test_agent_local() {
    local local_dir=$1
    if [ -z $1 ]; then
        usage
        exit -1
    fi
    echo "$INFO Run reproducible test for kata agent locally"
    ./$KATA_AGENT_TESTER $local_dir $KATA_AGENT_ARTIFEST $KATA_AGENT_RBCI_NAME
}

build_agent_image() {
    image_already=`sudo docker images| grep $KATA_AGENT_RBCI_NAME | awk {'print $1'}`
    if [ "$image_already" = "$KATA_AGENT_RBCI_NAME" ]; then
        echo "$INFO Detected image already exists, deleting it.."
        rm_agent_image
    fi
    echo "$INFO Build docker image for kata-agent rbc"
    ./$KATA_AGENT_BUILD_SCRIPT $KATA_AGENT_RBCI_NAME
}

rm_agent_image() {
    sudo docker rmi $KATA_AGENT_RBCI_NAME
}

clean() {
    echo "$INFO Cleaning all the temp files.." 
    rm -rf $KATA/$KATA_DIR
    rm -rf $RESULT_DIR
    echo "$INFO Done." 
}

main() {
    local feature=$1
    case $feature in
    agent-git)
        test_agent_git
        ;;
    agent-local)
        test_agent_local $2
        ;;
    agent-image)
        build_agent_image
        ;;
    agent-rmi)
        rm_agent_image
        ;;
    clean)
        clean
        ;;
    help)
        usage
        ;;
    *)
        usage
        ;;
    esac
}

main "$@"