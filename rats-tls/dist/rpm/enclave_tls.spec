%define centos_base_release 1
%define _debugsource_template %{nil}

%define __enclave_tls_install_post \
    cp %{_builddir}/%{PROJECT}-%{version}/%{name}/build/bin/sgx_stub_enclave.signed.so %{?buildroot}%{ENCLAVE_TLS_BINDIR} \
%{nil}

%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}}\
    %{__arch_install_post}\
    %{__os_install_post}\
    %{__enclave_tls_install_post}

%global _find_debuginfo_dwz_opts %{nil}
%global _dwz_low_mem_die_limit 0
%undefine _missing_build_ids_terminate_build

%global PROJECT inclavare-containers

%global ENCLAVE_TLS_ROOTDIR /opt/enclave-tls
%global ENCLAVE_TLS_BINDIR /usr/share/enclave-tls/samples
%global ENCLAVE_TLS_LIBDIR /opt/enclave-tls/lib
%global ENCLAVE_TLS_INCDIR /opt/enclave-tls/include

Name: enclave-tls
Version: 0.6.2
Release: %{centos_base_release}%{?dist}
Summary: enclave-tls is a protocol to establish secure and trusted channel by integrating enclave attestation with transport layer security.

Group: Development/Tools
License: Apache License 2.0
URL: https://github.com/alibaba/%{PROJECT}
Source0: https://github.com/alibaba/%{PROJECT}/archive/v%{version}.tar.gz

BuildRequires: git
BuildRequires: make
BuildRequires: autoconf
BuildRequires: libtool
BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: libsgx-dcap-quote-verify-devel
BuildRequires: libsgx-dcap-ql-devel
BuildRequires: libsgx-uae-service
ExclusiveArch: x86_64

%description
enclave-tls is a protocol to establish secure and trusted channel by integrating enclave attestation with transport layer security.

%prep
%setup -q -n %{PROJECT}-%{version}

%build
if [ -z "$SGX_SDK" ]; then
        SGX_SDK="/opt/intel/sgxsdk"
fi

# If the SGX SDK is not prepared well in build environment, stop the build
if [ ! -d "$SGX_SDK" ]; then
        echo 'Error: The SGX_SDK environment variable value is not correct'
        exit 1
fi

pushd %{name}
make SGX=1
popd

%install
pushd %{name}
Enclave_Tls_Root=%{?buildroot}%{ENCLAVE_TLS_ROOTDIR} Enclave_Tls_Bindir=%{?buildroot}%{ENCLAVE_TLS_BINDIR} make install
popd

%postun
rm -rf %{ENCLAVE_TLS_ROOTDIR} $(dirname %{ENCLAVE_TLS_BINDIR})

%files
%{ENCLAVE_TLS_BINDIR}/enclave-tls-server
%{ENCLAVE_TLS_BINDIR}/enclave-tls-client
%{ENCLAVE_TLS_BINDIR}/sgx_stub_enclave.signed.so
%{ENCLAVE_TLS_INCDIR}/*
%{ENCLAVE_TLS_LIBDIR}/libenclave_tls.so*
%{ENCLAVE_TLS_LIBDIR}/tls-wrappers/libtls_wrapper*.so*
%{ENCLAVE_TLS_LIBDIR}/crypto-wrappers/libcrypto_wrapper*.so*
%{ENCLAVE_TLS_LIBDIR}/attesters/libattester*.so*
%{ENCLAVE_TLS_LIBDIR}/verifiers/libverifier*.so*

%changelog
* Wed Jun 30 2021 Liang Yang <liang3.yang@intel.com> - 0.6.2
- Update to version 0.6.2.

* Thu Apr 22 2021 Shirong Hao <shirong@linux.alibaba.com> - 0.6.1
- Package init.
