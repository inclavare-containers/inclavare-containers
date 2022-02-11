# /usr/local
set(RATS_TLS_INSTALL_PATH "/usr/local")

# lib/rats_tls
set(RATS_TLS_INSTALL_LIB_PATH "${RATS_TLS_INSTALL_PATH}/lib/rats-tls")

# rats_tls/crypto-wrappers
set(RATS_TLS_INSTALL_LIBCW_PATH "${RATS_TLS_INSTALL_LIB_PATH}/crypto-wrappers")

# rats_tls/attesters
set(RATS_TLS_INSTALL_LIBA_PATH "${RATS_TLS_INSTALL_LIB_PATH}/attesters")

# rats_tls/verifiers
set(RATS_TLS_INSTALL_LIBV_PATH "${RATS_TLS_INSTALL_LIB_PATH}/verifiers")

# rats_tls/tls-wrappers
set(RATS_TLS_INSTALL_LIBTW_PATH "${RATS_TLS_INSTALL_LIB_PATH}/tls-wrappers")

# include/rats_tls
set(RATS_TLS_INSTALL_INCLUDE_PATH "${RATS_TLS_INSTALL_PATH}/include/rats-tls")

# rats_tls/sample
set(RATS_TLS_INSTALL_BIN_PATH "/usr/share/rats-tls/samples")

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
