%define centos_base_release 1
%define _debugsource_template %{nil}

%global PROJECT inclavare-containers
%global EPM_BIN_DIR /usr/local/bin
%global EPM_CONFIG_DIR /etc/epm
# to skip no build id error
%undefine _missing_build_ids_terminate_build

Name: epm
Version: %{EPM_VERSION}
Release: %{centos_base_release}%{?dist}
Summary: epm for Inclavare Containers(runE)
Group: Development/Tools
License: Apache License 2.0
URL: https://github.com/alibaba/%{PROJECT}
Source0: https://github.com/alibaba/%{PROJECT}/archive/v%{version}.tar.gz

ExclusiveArch: x86_64

%description
epm is a service that is used to manage the cache pools to optimize the startup time of enclave.

%prep
%setup -q -n %{PROJECT}-%{version}

%build
# we can't download go 1.13 through 'yum install' in centos, so that we check the go version in the '%build' section rather than in the 'BuildRequires' section.
if ! [ -x "$(command -v go)" ]; then
  echo 'Error: go is not installed. Please install Go 1.13 and above'
  exit 1
fi

NEED_GO_VERSION=13
CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//g' | sed 's/\./ /g' | awk '{print $2}')
if [ $CURRENT_GO_VERSION -lt $NEED_GO_VERSION  ]; then
  echo 'Error: go version is less than 1.13.0. Please install Go 1.13 and above'
  exit 1
fi

export GOPATH=${RPM_BUILD_DIR}/%{PROJECT}-%{version}
export GOPROXY="https://mirrors.aliyun.com/goproxy,direct"
cd epm
GOOS=linux make binaries

%install
install -d -p %{buildroot}%{EPM_BIN_DIR}
install -p -m 755 epm/bin/epm %{buildroot}%{EPM_BIN_DIR}

install -d -p %{buildroot}%{_defaultlicensedir}/%{name}
install -p -m 644 epm/LICENSE %{buildroot}%{_defaultlicensedir}/%{name}

%post
mkdir -p %{EPM_CONFIG_DIR}
cat << EOF > %{EPM_CONFIG_DIR}/config.toml
root = "/var/local/epm"
db_path = "/etc/epm/epm.db"
db_timeout = 10

[grpc]
  address = "/var/run/epm/epm.sock"
  uid = 0
  gid = 0
  max_recv_message_size = 16777216
  max_send_message_size = 16777216
EOF
cat << EOF > /etc/systemd/system/epm.service
[Unit]
Description=epm
Documentation=https://inclavare-containers.io
After=network.target

[Service]
ExecStart=/usr/local/bin/epm --config /etc/epm/config.toml --stderrthreshold=0
Restart=always
RestartSec=5
Delegate=yes
KillMode=process
OOMScoreAdjust=-999
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /var/run/epm
mkdir -p /var/local/epm
systemctl enable epm
systemctl start epm
%postun
rm -f %{EPM_CONFIG_DIR}/config.toml
systemctl disable epm
systemctl stop epm

%files
%{_defaultlicensedir}/%{name}/LICENSE
%{EPM_BIN_DIR}/epm

%changelog
* Mon Aug 30 2021 Liang Yang <liang3.yang@intel.com> - 0.6.3
- Update to version 0.6.3

* Wed Jun 30 2021 Liang Yang <liang3.yang@intel.com> - 0.6.2
- Update to version 0.6.2

* Mon May 24 2021 Liang Yang <liang3.yang@intel.com> - 0.6.1
- Update to version 0.6.1

* Mon Feb 8 2021 Zhiguang Jia <Zhiguang.Jia@linux.alibaba.com> - 0.6.0
- Update to version 0.6.0

* Wed Dec 30 2020 Zhiguang Jia <Zhiguang.Jia@linux.alibaba.com> - 0.5.2
- Update to version 0.5.2

* Mon Nov 30 2020 Zhiguang Jia <Zhiguang.Jia@linux.alibaba.com> - 0.5.1
- Update to version 0.5.1

* Thu Oct 29 2020 Zhiguang Jia <Zhiguang.Jia@linux.alibaba.com> - 0.5.0
- Update to version 0.5.0
