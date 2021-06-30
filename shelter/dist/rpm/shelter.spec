%define centos_base_release 1
%define _debugsource_template %{nil}

%global PROJECT inclavare-containers
%global BIN_DIR /usr/local/bin

Name: shelter
Version: 0.6.2
Release: %{centos_base_release}%{?dist}
Summary: shelter is designed as a remote attestation tool for customer to verify if their workloads are loaded in a specified intel authorized sgx enclaved.

Group: Development/Tools
License: Apache License 2.0
URL: https://github.com/alibaba/%{PROJECT}
Source0: https://github.com/alibaba/%{PROJECT}/archive/v%{version}.tar.gz

BuildRequires: openssl-devel
ExclusiveArch: x86_64

%description
shelter is designed as a remote attestation tool for customer to verify if their workloads are loaded in a specified intel authorized sgx enclaved.

%prep
%setup -q -n %{PROJECT}-%{version}

%build
# we can't download go 1.14 through 'yum install' in centos, so that we check the go version in the '%build' section rather than in the 'BuildRequires' section.
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
export PATH=$PATH:${GOPATH}/bin
export GO111MODULE=on
pushd %{name}
make
popd

%install
install -d -p %{buildroot}%{BIN_DIR}
install -p -m 755 %{name}/%{name} %{buildroot}%{BIN_DIR}

%files
%{BIN_DIR}/%{name}

%changelog
* Wed Jun 30 2021 Zhiming Hu <zhiming.hu@intel.com> - 0.6.2
- Update to version 0.6.2

* Sat May 22 2021 Yilin Li <YiLin.Li@linux.alibaba.com> - 0.6.1
- Update to version 0.6.1.

* Thu Apr 15 2021 Zhiming Hu <zhiming.hu@intel.com> - 0.6.0
- Package init.
