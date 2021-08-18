include(FindPackageHandleStandardArgs)

set(INTEL_SGXSSL_ROOT ${ETLS_SRC_PATH}/src/external/sgx-ssl/intel-sgx-ssl)
set(INTEL_SGXSSL_SRC ${INTEL_SGXSSL_ROOT}/src/intel-sgx-ssl)
set(INTEL_SGXSSL_LIB ${INTEL_SGXSSL_SRC}/Linux/package/lib64)
set(OPENSSL_DIR ${INTEL_SGXSSL_SRC}/openssl_source)
set(INTEL_SGXSSL_LIB_PATH ${CMAKE_BINARY_DIR}/src/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/lib64)
