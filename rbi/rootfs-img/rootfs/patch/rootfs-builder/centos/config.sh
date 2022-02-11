#
# Copyright (c) 2018 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

OS_NAME="Centos"

OS_VERSION=${OS_VERSION:-7}

LOG_FILE="/var/log/yum-centos.log"

MIRROR_LIST="http://mirrorlist.centos.org/?release=${OS_VERSION}&arch=${ARCH}&repo=os&container=container"

# Aditional Repos
CENTOS_UPDATES_MIRROR_LIST="http://mirrorlist.centos.org/?release=${OS_VERSION}&arch=${ARCH}&repo=updates&container=container"

CENTOS_EXTRAS_MIRROR_LIST="http://mirrorlist.centos.org/?release=${OS_VERSION}&arch=${ARCH}&repo=extras&container=container"

CENTOS_PLUS_MIRROR_LIST="http://mirrorlist.centos.org/?release=${OS_VERSION}&arch=${ARCH}&repo=centosplus&container=container"

GPG_KEY_URL="https://www.centos.org/keys/RPM-GPG-KEY-CentOS-7"

GPG_KEY_FILE="RPM-GPG-KEY-CentOS-7"

PACKAGES="nss-tools-3.44.0-7"
PACKAGES+=" rpm-4.11.3-45"
PACKAGES+=" keyutils-libs-1.5.8-3"
PACKAGES+=" glibc-2.17-317"
PACKAGES+=" popt-1.13-16"
PACKAGES+=" setup-2.8.71-11"
PACKAGES+=" glibc-common-2.17-317"
PACKAGES+=" p11-kit-0.23.5-3"
PACKAGES+=" libacl-2.2.51-15"
PACKAGES+=" coreutils-8.22-24"
PACKAGES+=" libdb-utils-5.3.21-25"
PACKAGES+=" libcap-2.22-11"
PACKAGES+=" nss-3.44.0-7"
PACKAGES+=" krb5-libs-1.15.1-50"
PACKAGES+=" pcre-8.32-17"
PACKAGES+=" chkconfig-1.7.6-1"
PACKAGES+=" cyrus-sasl-lib-2.1.26-23"
PACKAGES+=" sqlite-3.7.17-8"
PACKAGES+=" libattr-2.4.46-13"
PACKAGES+=" nss-sysinit-3.44.0-7"
PACKAGES+=" gawk-4.0.2-4"
PACKAGES+=" audit-libs-2.8.5-4"
PACKAGES+=" readline-6.2-11"
PACKAGES+=" nss-util-3.44.0-4"
PACKAGES+=" basesystem-10.0-7"
PACKAGES+=" libsepol-2.5-10"
PACKAGES+=" libcom_err-1.42.9-19"
PACKAGES+=" zlib-1.2.7-18"
PACKAGES+=" libverto-0.2.5-4"
PACKAGES+=" p11-kit-trust-0.23.5-3"
PACKAGES+=" nss-pem-1.0.3-7"
PACKAGES+=" grep-2.20-3"
PACKAGES+=" info-5.1-5"
PACKAGES+=" centos-release-7-9.2009.0"
PACKAGES+=" filesystem-3.2-25"
PACKAGES+=" libdb-5.3.21-25"
PACKAGES+=" 1:findutils-4.5.11-6"
PACKAGES+=" libselinux-2.5-15"
PACKAGES+=" bzip2-libs-1.0.6-13"
PACKAGES+=" rpm-libs-4.11.3-45"
PACKAGES+=" libcap-ng-0.7.5-4"
PACKAGES+=" 1:gmp-6.0.0-15"
PACKAGES+=" elfutils-libelf-0.176-5"
PACKAGES+=" ncurses-libs-5.9-14.20130511"
PACKAGES+=" nss-softokn-freebl-3.44.0-8"
PACKAGES+=" xz-libs-5.2.2-1"
PACKAGES+=" 1:openssl-libs-1.0.2k-19"
PACKAGES+=" tzdata-2020a-1"
PACKAGES+=" libidn-1.28-4"
PACKAGES+=" libcurl-7.29.0-59"
PACKAGES+=" sed-4.2.2-7"
PACKAGES+=" nss-softokn-3.44.0-8"
PACKAGES+=" libssh2-1.8.0-4"
PACKAGES+=" ncurses-base-5.9-14.20130511"
PACKAGES+=" curl-7.29.0-59"
PACKAGES+=" openldap-2.4.44-22"
PACKAGES+=" libstdc++-4.8.5-44"
PACKAGES+=" libtasn1-4.10-1"
PACKAGES+=" bash-4.2.46-34"
PACKAGES+=" ncurses-5.9-14.20130511"
PACKAGES+=" nspr-4.21.0-1"
PACKAGES+=" lua-5.1.4-15"
PACKAGES+=" libgcc-4.8.5-44"
PACKAGES+=" libffi-3.0.13-19"

#Optional packages:
# systemd: An init system that will start kata-agent if kata-agent
#          itself is not configured as init process.
[ "$AGENT_INIT" == "no" ] && PACKAGES+=" systemd-219-78" || true

# Init process must be one of {systemd,kata-agent}
INIT_PROCESS=systemd
# List of zero or more architectures to exclude from build,
# as reported by  `uname -m`
ARCH_EXCLUDE_LIST=()

[ "$SECCOMP" = "yes" ] && PACKAGES+=" libseccomp" || true
