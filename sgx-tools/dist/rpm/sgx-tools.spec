%define centos_base_release 1
%define _debugsource_template %{nil}

%global PROJECT inclavare-containers
%global BIN_DIR /usr/local/bin

Name: sgx-tools
Version: 0.6.3
Release: %{centos_base_release}%{?dist}
Summary: sgx-tools is a commandline tool, used to interact Intel SGX aesm service.

Group: Development/Tools
License: Apache License 2.0
URL: https://github.com/alibaba/%{PROJECT}
Source0: https://github.com/alibaba/%{PROJECT}/archive/v%{version}.tar.gz

BuildRequires: libsgx-dcap-quote-verify-devel
ExclusiveArch: x86_64

%description
sgx-tools is a command line tool for inclavare-containers. Interact Intel SGX aesm service to retrieve various materials such as launch token, Quoting Enclave's target information, enclave quote and enclave remote attestation report from IAS.

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
* Mon Aug 30 2021 Shirong Hao <shirong@linux.alibaba.com> - 0.6.3
- Update to version 0.6.3

* Wed Jun 30 2021 Shirong Hao <shirong@linux.alibaba.com> - 0.6.2
- Update to version 0.6.2

* Mon May 24 2021 Shirong Hao <shirong@linux.alibaba.com> - 0.6.1
- Update to version 0.6.1

* Sun Feb 07 2021 Shirong Hao <shirong@linux.alibaba.com> - 0.6.0
- Update to version 0.6.0

* Wed Dec 30 2020 Shirong Hao <shirong@linux.alibaba.com> - 0.5.2
- Update to version 0.5.2

* Mon Nov 30 2020 Shirong Hao <shirong@linux.alibaba.com> - 0.5.1
- Update to version 0.5.1

* Tue Nov 24 2020 Yilin Li <YiLin.Li@linux.alibaba.com> - 0.5.0-2
- Drop unnecessary dependency

* Wed Oct 28 2020 Shirong Hao <shirong@linux.alibaba.com> - 0.5.0
- Update to version 0.5.0

* Wed Sep 23 2020 Shirong Hao <shirong@linux.alibaba.com> - 0.4.1
- Package init.
