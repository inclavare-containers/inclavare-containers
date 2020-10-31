%define centos_base_release 1
%define _debugsource_template %{nil}

%global PROTOBUF_VERSION 1.3.5
%global PROJECT inclavare-containers
%global BIN_DIR /usr/local/bin

Name: rune
Version: 0.5.0
Release: %{centos_base_release}%{?dist}
Summary: CLI tool for spawning and running enclaves in containers according to the OCI specification.  

Group: Development/Tools
License: Apache License 2.0
URL: https://github.com/alibaba/%{PROJECT}
Source0: https://github.com/alibaba/%{PROJECT}/archive/v%{version}.tar.gz

BuildRequires: protobuf >= 3
BuildRequires: protobuf-compiler
BuildRequires: libseccomp-devel
ExclusiveArch: x86_64

%description
rune is a CLI tool for spawning and running enclaves in containers according to the OCI specification. The codebase of rune is a fork of runc, so rune can be used as runc if enclave is not configured or available.

%prep
%setup -q -n %{PROJECT}-%{version}

%build
# we cann't download go1.14 through 'yum install' in centos, so that wo check the go version in the '%build' section rather than in the 'BuildRequires' section.
if ! [ -x "$(command -v go)" ]; then
  echo 'Error: go is not installed. Please install Go 1.14 and above'
  exit 1
fi

NEED_GO_VERSION=14
CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//g' | sed 's/\./ /g' | awk '{print $2}')
if [ $CURRENT_GO_VERSION -lt $NEED_GO_VERSION  ]; then
  echo 'Error: go version is less than 1.14.0. Please install Go 1.14 and above'
  exit 1
fi

export GOPATH=${RPM_BUILD_DIR}/%{PROJECT}-%{version}
export GOPROXY="https://mirrors.aliyun.com/goproxy,direct"
export PATH=$PATH:${GOPATH}/bin
export GO111MODULE=on
go get github.com/golang/protobuf/protoc-gen-go@v%{PROTOBUF_VERSION}
pushd %{name}
make
popd

%install
install -d -p %{buildroot}%{BIN_DIR}
install -p -m 755 %{name}/%{name} %{buildroot}%{BIN_DIR}

install -d -p %{buildroot}%{_defaultlicensedir}/%{name}-%{version}
install -p -m 644 %{name}/LICENSE %{buildroot}%{_defaultlicensedir}/%{name}-%{version}

%files
%{_defaultlicensedir}/%{name}-%{version}/LICENSE
%{BIN_DIR}/%{name}

%changelog
* Wed Oct 28 2020 Shirong Hao <shirong@linux.alibaba.com> - 0.5.0
- Update to version 0.5.0

* Wed Sep 23 2020 Shirong Hao <shirong@linux.alibaba.com> - 0.4.1
- Update to version 0.4.1

* Sun Aug 30 2020 Shirong Hao <shirong@linux.alibaba.com> - 0.4.0
- Update to version 0.4.0

* Tue Jul 28 2020 shirong <shirong@linux.alibaba.com> - 0.3.0 
- Update to version 0.3.0

* Fri Jul 10 2020 Yilin Li <YiLin.Li@linux.alibaba.com> - 0.2.0
- Package init.
