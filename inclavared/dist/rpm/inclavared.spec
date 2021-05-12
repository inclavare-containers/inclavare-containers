%define centos_base_release 1
%define _debugsource_template %{nil}

%global PROJECT inclavare-containers
%global BIN_DIR /usr/local/bin

Name: inclavared
Version: 0.6.1
Release: %{centos_base_release}%{?dist}
Summary: inclavared is a coordinator which creates a m-TLS(Mutal Transport Layer Security) connection between stub enclave and other enclaves with remote attestation.

Group: Development/Tools
License: Apache License 2.0
URL: https://github.com/alibaba/%{PROJECT}
Source0: https://github.com/alibaba/%{PROJECT}/archive/v%{version}.tar.gz

BuildRequires: enclave-tls == %{version}
ExclusiveArch: x86_64

%description
inclavared is a coordinator which creates a m-TLS(Mutal Transport Layer Security) connection between stub enclave and other enclaves with remote attestation.

%prep
%setup -q -n %{PROJECT}-%{version}

%build
if ! [ -x "$(command -v rustc)" ]; then
  echo 'Error: Rust is not installed. Please type the "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; source $HOME/.cargo/env" command to install Rust firstly'
  exit 1
fi

if ! [ -x "$(command -v cargo)" ]; then
   echo 'Error: Cargo is not installed. Please type the "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; source $HOME/.cargo/env" command to install Cargo firstly'
   exit 1
fi

pushd %{name}
make
popd

%install
install -d -p %{buildroot}%{BIN_DIR}
install -p -m 755 %{name}/bin/%{name} %{buildroot}%{BIN_DIR}

%files
%{BIN_DIR}/%{name}

%changelog
* Sat May  8 2021 Tianjia Zhang <tianjia.zhang@linux.alibaba.com> - 0.6.1
- Package init.
