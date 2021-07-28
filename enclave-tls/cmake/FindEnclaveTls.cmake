include(CustomInstallDirs)
include(FindPackageHandleStandardArgs)

set(ENCLAVE_TLS_INCLUDE_DIR ${ETLS_SRC_PATH}/src/include)

# Handle the QUIETLY and REQUIRED arguments and set ENCLAVE_TLS_FOUND to TRUE if all listed variables are TRUE.
find_package_handle_standard_args(ENCLAVE_TLS
    DEFAULT_MSG
    ENCLAVE_TLS_INCLUDE_DIR)

if(ENCLAVE_TLS_FOUND)
    set(ENCLAVE_TLS_INCLUDES ${ENCLAVE_TLS_INCLUDE_DIR})
else()
    set(ENCLAVE_TLS_LIBRARIES)
    set(ENCLAVE_TLS_INCLUDES)
endif()
