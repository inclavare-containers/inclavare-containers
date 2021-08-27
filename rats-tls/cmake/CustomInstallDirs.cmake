# /usr/local
set(ENCLAVE_TLS_INSTALL_PATH "/usr/local")

# lib/enclave_tls
set(ENCLAVE_TLS_INSTALL_LIB_PATH "${ENCLAVE_TLS_INSTALL_PATH}/lib/enclave-tls")

# enclave_tls/crypto-wrappers
set(ENCLAVE_TLS_INSTALL_LIBCW_PATH "${ENCLAVE_TLS_INSTALL_LIB_PATH}/crypto-wrappers")

# enclave_tls/attesters
set(ENCLAVE_TLS_INSTALL_LIBA_PATH "${ENCLAVE_TLS_INSTALL_LIB_PATH}/attesters")

# enclave_tls/verifiers
set(ENCLAVE_TLS_INSTALL_LIBV_PATH "${ENCLAVE_TLS_INSTALL_LIB_PATH}/verifiers")

# enclave_tls/tls-wrappers
set(ENCLAVE_TLS_INSTALL_LIBTW_PATH "${ENCLAVE_TLS_INSTALL_LIB_PATH}/tls-wrappers")

# include/enclave_tls
set(ENCLAVE_TLS_INSTALL_INCLUDE_PATH "${ENCLAVE_TLS_INSTALL_PATH}/include/enclave-tls")

# enclave_tls/sample
set(ENCLAVE_TLS_INSTALL_BIN_PATH "/usr/share/enclave-tls/samples")

# sgx sdk
if(EXISTS $ENV{SGX_SDK})
    set(SGXSDK_INSTALL_PATH "$ENV{SGX_SDK}")
else()
    set(SGXSDK_INSTALL_PATH "/opt/intel/sgxsdk")
endif()

# sgx sdk library
set(SGXSDK_INSTALL_LIB_PATH "${SGXSDK_INSTALL_PATH}/lib64")

# sgx sdk include
set(SGXSDK_INSTALL_INCLUDE_PATH "${SGXSDK_INSTALL_PATH}/include")
