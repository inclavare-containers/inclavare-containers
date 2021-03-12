package constants

type EnclaveType string

const (
	IntelSGX = EnclaveType("intelSgx")
)

const (
	EnclaveTypeKeyName        = "ENCLAVE_TYPE"
	EnclaveRuntimePathKeyName = "ENCLAVE_RUNTIME_PATH"
	EnclaveRuntimeArgsKeyName = "ENCLAVE_RUNTIME_ARGS"
	DefaultEnclaveRuntimeArgs = "./"
)

const (
	ReplaceOcclumImageScript = `#!/bin/bash
set -xe
function usage() {
  if [ $# -lt 2 ]; then
    echo "usage: $0 src_dir dst_dir"
    exit 1
  fi
}

function deep_copy_link() {
  local link_symbol=$1
  local link_target=$2
  rm -f ${link_symbol}
  mkdir -p ${link_symbol}
  /bin/cp -rdf ${link_target}/* ${link_symbol} || true
}

function copy(){
  local src_dir=$1
  local dst_dir=$2
  local dst_root_dir=$3

  if [ ! -d ${dst_dir} ]; then
    mkdir -p ${dst_dir}
  fi

  for file in $(ls ${src_dir}/)
  do
    src_file=${src_dir}/${file}
    dst_file=${dst_dir}/${file}
    if [ -f ${src_file} ]; then
      rm -fr ${dst_file}
      /bin/cp -df ${src_file} ${dst_file}
    elif [ -d ${src_file} ]; then
	    link_target=$(stat -c "%N" ${dst_file} | awk '-F-> ' '{print $2}' | awk -F"'" '{print $2}')
      if [ "${link_target}" != "" ]; then
        reg='^/.*'
        if [[  ${link_target} =~ ${reg}  ]]; then
          link_target=${dst_root_dir}${link_target}
        else
          link_target=${dst_file}/../${link_target}
        fi
        deep_copy_link "${dst_file}" "${link_target}"
      fi
      copy "${src_file}" "${dst_file}" "${dst_root_dir}"
    fi
  done
}

function compact() {
  local src_dir=$1
  local dst_dir=$2
  backup_dir=/tmp/dst_backup
  # step1: backup files in directory dst_dir
  rm -fr ${backup_dir}
  mkdir -p ${backup_dir}
  /bin/cp -rdf ${dst_dir}/* ${backup_dir}/ || true
  # step2: clean dirctory dst_dir
  rm -rf ${dst_dir}/*
  # step3: copy files in directory src_dir to directory dst_dir
  /bin/cp -rdf ${src_dir}/* ${dst_dir}/ || true
  # step4: restore backuped failes to directory ${dst_dir}
  copy ${backup_dir} ${dst_dir} ${dst_dir}
  # step5: remove backuped files
  rm -rf ${backup_dir}
}

function start() {
  usage $@
  compact $@
}

start $@`

	CarrierScript = `#!/bin/bash
set -xe
base_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
occlum_workspace=${base_dir}/occlum_workspace

temp=$(getopt -a -o a:r:w:p:c:e:u:m:s:k:n: -l action:,rootfs:,work_dir:,entry_point:,occlum_config_path:,enclave_config_path:,\
unsigned_enclave_path:,unsigned_material_path:,signed_enclave_path:,public_key_path:,signature_path: -- "$@")
eval set -- "$temp"

while true
do
  case "$1" in
    -a|--action)
      action=$2; shift;;
    -r|--rootfs)
      rootfs=$2; shift;;
    -w|--work_dir)
      work_dir=$2; shift;;
    -p|--entry_point)
      entry_point=$2; shift;;
    -c|--occlum_config_path)
      occlum_config_path=$2; shift;;
    -e|--enclave_config_path)
      enclave_config_path=$2; shift;;
    -u|--unsigned_enclave_path)
      unsigned_enclave_path=$2; shift;;
    -m|--unsigned_material_path)
      unsigned_material_path=$2; shift;;
    -s|--signed_enclave_path)
      signed_enclave_path=$2; shift;;
    -k|--public_key_path)
      public_key_path=$2; shift;;
    -n|--signature_path)
      signature_path=$2; shift;;
    --)
      shift
      break
      ;;
    *)
      echo "Unknown argument: $1"; shift;;
  esac
shift
done

function copyOcclumLiberaries() {
  pushd ${rootfs}/${work_dir}
  local lib_dir=${rootfs}/lib
  /bin/cp -f /usr/lib/x86_64-linux-gnu/libprotobuf.so ${lib_dir}
  /bin/cp -f /lib/x86_64-linux-gnu/libseccomp.so.2 ${lib_dir}
  /bin/cp -f /usr/lib/libsgx_u*.so* ${lib_dir}
  /bin/cp -f /usr/lib/libsgx_enclave_common.so.1 ${lib_dir}
  /bin/cp -f /usr/lib/libsgx_launch.so.1 ${lib_dir}
  #/bin/cp -f ./build/lib/libocclum-pal.so ${lib_dir}/liberpal-occlum.so
  #ln -sfn ./build/lib/libocclum-pal.so liberpal-occlum.so
  #chroot ${rootfs} /sbin/ldconfig
  popd
}

function generateEnclaveConfiguration() {
  occlum_config_path=$1
  enclave_config_path=$2
  occlum_instance_dir=$3
  if [ ! -f ${occlum_config_path} ]; then
    echo "GenerateEnclaveConfiguration: ${occlum_config_path} is not exist"
    exit 1
  fi
  /opt/occlum/build/bin/gen_internal_conf --user_json ${occlum_config_path} gen_user_conf --sdk_xml ${enclave_config_path}  \
  --user_fs_mac $(LD_LIBRARY_PATH="/opt/occlum/sgxsdk-tools/sdk_libs" /opt/occlum/build/bin/occlum-protect-integrity show-mac ${occlum_instance_dir}/build/mount/__ROOT/metadata) \
  --output_user_json ${occlum_instance_dir}/build/Occlum.json
}

function buildUnsignedEnclave(){
  if [[ "${rootfs}" == "" || "${work_dir}" == "" || "${occlum_config_path}" == "" ]]; then
    echo "BuildUnsignedEnclave:: the arguments should not be empty: rootfs, work_dir, occlum_config_path"
    exit 1
  fi
  export PATH=$PATH:/opt/occlum/build/bin/
  rm -fr ${occlum_workspace}
  mkdir -p ${occlum_workspace}
  pushd ${occlum_workspace}
  # occlum init
  occlum init
  # copy Occlum.json to occlum workspace
  if [ -f ${occlum_config_path} ];then
    /bin/cp -f ${occlum_config_path} Occlum.json
  fi
  # build occlum image
  /bin/bash ${base_dir}/replace_occlum_image.sh ${rootfs} image
  # occlum build
  empty_sign_tool=$(mktemp sign_tool.XXXXXX)
  #occlum build --sign-tool ${empty_sign_tool} || true
  occlum build
  if [ ! -f ./build/lib/libocclum-libos.so ]; then
    if [ -f ./build/lib/libocclum-libos.so.0 ]; then
      pushd ./build/lib/
      ln -s libocclum-libos.so.0 libocclum-libos.so
      popd
    fi
  fi
  # generate the configuration file Enclave.xml that used by enclave from Occlum.json
  generateEnclaveConfiguration ${occlum_workspace}/Occlum.json ${occlum_workspace}/Enclave.xml ${occlum_workspace}
  mkdir -p ${rootfs}/${work_dir} || true
  rm -fr image
  /bin/cp -fr . ${rootfs}/${work_dir}
  popd
  rm -fr ${occlum_workspace}
}

function buildUnsignedEnclaveWithBundleCache0(){
  if [[ "${rootfs}" == "" || "${work_dir}" == "" || "${occlum_config_path}" == "" ]]; then
    echo "BuildUnsignedEnclave:: the arguments should not be empty: rootfs, work_dir, occlum_config_path"
    exit 1
  fi
  export PATH=$PATH:/opt/occlum/build/bin/
  occlum_instance_dir=${rootfs}/${work_dir}
  pushd ${occlum_instance_dir}
  /bin/cp -f ${occlum_config_path} Occlum.json
  # occlum build
  occlum build
  if [ ! -f ./build/lib/libocclum-libos.so ]; then
    if [ -f ./build/lib/libocclum-libos.so.0 ]; then
      pushd ./build/lib/
      ln -s libocclum-libos.so.0 libocclum-libos.so
      popd
    fi
  fi
  #gen_enclave_conf -i Occlum.json -o Enclave.xml
  generateEnclaveConfiguration ${occlum_instance_dir}/Occlum.json ${occlum_instance_dir}/Enclave.xml ${occlum_instance_dir}
  popd
}

function generateSigningMaterial() {
  if [[ "${enclave_config_path}" == "" || "${unsigned_enclave_path}" == "" || "${unsigned_material_path}" == ""  ]]; then
    echo "GenerateSigningMaterial:: the argumentes should not be empty: enclave_config_path, unsigned_enclave_path, unsigned_material_path"
    exit 1
  fi
  #if [[ -f ${occlum_json_file_path} && ! -f ${enclave_config_path} ]]; then
  #	/opt/occlum/build/bin/gen_enclave_conf -i ${occlum_json_file_path} -o ${enclave_config_path}
  #fi
  /opt/intel/sgxsdk/bin/x64/sgx_sign gendata -enclave ${unsigned_enclave_path} -config ${enclave_config_path} -out ${unsigned_material_path}
}

function cascadeEnclaveSignature() {
  if [[ "${enclave_config_path}" == "" || "${unsigned_enclave_path}" == "" || "${unsigned_material_path}" == "" \
	|| "${signed_enclave_path}" == "" || "${public_key_path}" == "" || "${signature_path}" == "" ]]; then
    echo "CascadeEnclaveSignature:: the argumentes should not be empty: enclave_config_path, unsigned_enclave_path, unsigned_material_path, signed_enclave_path, public_key_path, signature_path"
    exit 1
  fi
  /opt/intel/sgxsdk/bin/x64/sgx_sign catsig -enclave ${unsigned_enclave_path} -config ${enclave_config_path} -out ${signed_enclave_path} -key ${public_key_path} \
    -sig ${signature_path} -unsigned ${unsigned_material_path}
}

function mockSignature() {
  if [[ "${public_key_path}" == "" || "${signature_path}" == "" || "${unsigned_material_path}" == "" ]]; then
    echo "MockSignature:: the argumentes should not be empty: public_key_path, signature_path, unsigned_material_path"
    exit 1
  fi
  dir=$(mktemp -d)
  openssl genrsa -out ${dir}/privatekey.pem -3 3072
  openssl rsa -in ${dir}/privatekey.pem -pubout -out ${public_key_path}
  openssl dgst -sha256 -out ${signature_path} -sign ${dir}/privatekey.pem -keyform PEM ${unsigned_material_path}
  rm -fr ${dir}
}

function doAction(){
  if [ "${action}" == "" ]; then
    echo "the argument should not be empty: action"
    exit 1
  fi
  case ${action} in
    buildUnsignedEnclave)
      buildUnsignedEnclave
      ;;
	buildUnsignedEnclaveWithBundleCache0)
      buildUnsignedEnclaveWithBundleCache0
      ;;
    generateSigningMaterial)
      generateSigningMaterial
      ;;
    cascadeEnclaveSignature)
      cascadeEnclaveSignature
      ;;
    mockSignature)
      mockSignature
      ;;
    *)
      echo "unknown action: ${action}"
      exit 1
      ;;
  esac
}

doAction`
)
