package constants

type EnclaveType string

const (
	IntelSGX = EnclaveType("intelSgx")
)

const (
	EnclaveTypeKeyName        = "ENCLAVE_TYPE"
	EnclaveRuntimePathKeyName = "ENCLAVE_RUNTIME_PATH"
	EnclaveRuntimeArgsKeyName = "ENCLAVE_RUNTIME_ARGS"
	DefaultEnclaveRuntimeArgs = ".occlum"
	OcclumConfigPathKeyName   = "OCCLUM_CONFIG_PATH"
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

	//FIXME
	BuildOcclumEnclaveScript = `#!/bin/bash
		set -xe
		data_dir=/data
		rootfs=/rootfs
		work_dir=%s
		entry_point=%s
		occlum_config_path=${rootfs}/%s
		occlum_workspace=${data_dir}/../occlum_workspace
		rm -fr ${occlum_workspace}
		mkdir -p ${occlum_workspace}
		pushd ${occlum_workspace}
		occlum init
		if [[ "${occlum_config_path}" != "" && -f ${occlum_config_path} ]];then
			/bin/cp -f ${occlum_config_path} Occlum.json
		fi
		sed -i "s#/bin#${entry_point}#g" Occlum.json
		/bin/bash ${data_dir}/replace_occlum_image.sh ${rootfs} image
		occlum build
		rm -f ${rootfs}/${work_dir}/.occlum/build/lib/libocclum-libos.signed.so
		mkdir -p ${rootfs}/${work_dir} || true
		/bin/cp -fr .occlum ${rootfs}/${work_dir}
        # ===fixme debug====
        /bin/cp -fr image ${rootfs}/${work_dir}
        /bin/cp -f Occlum.json ${rootfs}/${work_dir}
        # ==================
		/bin/cp -f Enclave.xml ${data_dir}
		popd
		pushd ${rootfs}/${work_dir}
		# ==== copy sgxsdk libs =======
		lib_dir=${rootfs}/lib
		/bin/cp -f /usr/lib/x86_64-linux-gnu/libprotobuf.so ${lib_dir}
		/bin/cp -f /lib/x86_64-linux-gnu/libseccomp.so.2 ${lib_dir}
		/bin/cp -f /usr/lib/libsgx_u*.so* ${lib_dir}
		/bin/cp -f /usr/lib/libsgx_enclave_common.so.1 ${lib_dir} 
		/bin/cp -f /usr/lib/libsgx_launch.so.1 ${lib_dir}
		# ==================
		ln -sfn .occlum/build/lib/libocclum-pal.so liberpal-occlum.so
		chroot ${rootfs} /sbin/ldconfig
		popd
		`
)
