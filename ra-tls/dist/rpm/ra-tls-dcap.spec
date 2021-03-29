%define centos_base_release 1
%define _debugsource_template %{nil}

%global PROJECT inclavare-containers
%global BIN_DIR /usr/local/bin

Name: ra-tls
Version: 0.6.0
Release: %{centos_base_release}%{?dist}
Summary: CLI tool for remote attestation through tls in containers.

Group: Development/Tools
License: Apache License 2.0
URL: https://github.com/alibaba/%{PROJECT}
Source0: https://github.com/alibaba/%{PROJECT}/archive/v%{version}.tar.gz

BuildRequires: git
BuildRequires: make
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: libtool
ExclusiveArch: x86_64

%description
ra-tls is a CLI tool for remote attestation through tls in containers.

%prep
%setup -q -n %{PROJECT}-%{version}

%build
pushd %{name}
make ECDSA=1
popd

%install
install -d -p %{buildroot}%{BIN_DIR}
install -p -m 755 %{name}/build/bin/elv %{buildroot}%{BIN_DIR}
install -p -m 755 %{name}/build/bin/ra-tls-server %{buildroot}%{BIN_DIR}
# install -p -m 755 %{name}/build/bin/wolfssl-config %{buildroot}%{BIN_DIR}
# install -p -m 755 %{name}/build/bin/Wolfssl_Enclave.signed.so %{buildroot}%{BIN_DIR}

%post
mkdir -p /run/rune

%files
 %{BIN_DIR}/%{name}-server
 %{BIN_DIR}/elv
# %{BIN_DIR}/wolfssl-config
# %{BIN_DIR}/Wolfssl_Enclave.signed.so

%changelog
* Mon Mar 29 2021 Yilin Li <YiLin.Li@linux.alibaba.com> - 0.6.0
- Package init.
